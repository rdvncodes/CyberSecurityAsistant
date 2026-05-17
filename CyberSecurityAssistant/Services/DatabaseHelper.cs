using System.IO;
using Microsoft.Data.Sqlite;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System;
using System.Linq;
using System.Windows;
using System.Windows.Media;

namespace CyberSecurityAssistant.Services
{
    public static class DatabaseHelper
    {
        private static readonly string _dbPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "siberkalkan.db");
        private static string ConnectionString => $"Data Source={_dbPath}";

        public static void InitializeDatabase()
        {
            using var connection = new SqliteConnection(ConnectionString);
            connection.Open();

            var command = connection.CreateCommand();
            command.CommandText = @"
                PRAGMA foreign_keys = ON;

                CREATE TABLE IF NOT EXISTS kullanicilar (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    eposta TEXT NOT NULL UNIQUE,
                    gorunen_ad TEXT,
                    sifre TEXT,
                    olusturulma_tarihi TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS klasorler (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ad TEXT NOT NULL,
                    tip TEXT NOT NULL,
                    kullanici_id INTEGER,
                    gmail_klasor_id TEXT,
                    FOREIGN KEY (kullanici_id) REFERENCES kullanicilar(id)
                );

                CREATE TABLE IF NOT EXISTS mailler (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    klasor_id INTEGER NOT NULL,
                    konu TEXT,
                    icerik TEXT,
                    gonderen_eposta TEXT,
                    alici_eposta TEXT,
                    gonderen_ad TEXT,
                    tarih TEXT,
                    okundu_mu INTEGER DEFAULT 0,
                    spam_mi INTEGER DEFAULT 0,
                    phishing_mi INTEGER DEFAULT 0,
                    phishing_skoru REAL DEFAULT 0,
                    spam_skoru REAL DEFAULT 0,
                    gmail_mesaj_id TEXT,
                    ek_var_mi INTEGER DEFAULT 0,
                    FOREIGN KEY (klasor_id) REFERENCES klasorler(id)
                );

                -- Python ile tam uyumlu loglama tabloları
                CREATE TABLE IF NOT EXISTS analiz_loglari (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    islenen_metin TEXT,
                    tip TEXT,
                    skor REAL,
                    sonuc TEXT,
                    gonderen_adres TEXT,
                    konu TEXT,
                    tarih TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS zararli_linkler (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    log_id INTEGER,
                    url_adresi TEXT,
                    domain TEXT,
                    virustotal_durumu TEXT,
                    FOREIGN KEY(log_id) REFERENCES analiz_loglari(id)
                );

                CREATE TABLE IF NOT EXISTS ekli_dosyalar (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    log_id INTEGER,
                    dosya_adi TEXT,
                    dosya_hash TEXT,
                    virustotal_skoru INTEGER,
                    FOREIGN KEY(log_id) REFERENCES analiz_loglari(id)
                );

                CREATE TABLE IF NOT EXISTS sistem_loglari (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    islem_tipi TEXT,
                    islem_detayi TEXT,
                    islem_tarihi TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS gmail_hesaplari (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kullanici_id INTEGER,
                    eposta TEXT NOT NULL,
                    uygulama_sifresi TEXT,
                    son_senkronizasyon TEXT,
                    imap_sunucu TEXT DEFAULT 'imap.gmail.com',
                    imap_port INTEGER DEFAULT 993,
                    smtp_sunucu TEXT DEFAULT 'smtp.gmail.com',
                    smtp_port INTEGER DEFAULT 587,
                    FOREIGN KEY (kullanici_id) REFERENCES kullanicilar(id)
                );

                CREATE TABLE IF NOT EXISTS ayarlar (
                    anahtar TEXT PRIMARY KEY,
                    deger TEXT
                );

                -- Kullanıcının manuel olarak şüpheli işaretlediği mail göndericileri.
                -- Bu listedeki adreslerden gelen mailler analiz edilmeden otomatik Çöp Kutusu'na taşınır.
                CREATE TABLE IF NOT EXISTS supheli_gondericiler (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    eposta TEXT NOT NULL UNIQUE,
                    eklenme_tarihi TEXT DEFAULT CURRENT_TIMESTAMP,
                    notlar TEXT DEFAULT ''
                );

                -- VirusTotal yanıt önbelleği. Aynı URL/dosya 24 saat içinde tekrar taranırsa
                -- VT API'sini aramaz, bu tablodaki sonucu döndürür → rate limit korunur, hız artar.
                CREATE TABLE IF NOT EXISTS vt_cache (
                    cache_key TEXT PRIMARY KEY,         -- url hash veya file hash (sha256)
                    scan_type TEXT NOT NULL,            -- 'url' | 'file'
                    malicious INTEGER DEFAULT 0,
                    suspicious INTEGER DEFAULT 0,
                    harmless INTEGER DEFAULT 0,
                    undetected INTEGER DEFAULT 0,
                    vendor_json TEXT,                   -- VendorDetails JSON serialize
                    threat_type TEXT,                   -- TopThreatType() (Trojan/Phishing/...)
                    cached_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_vt_cache_at ON vt_cache(cached_at);

                CREATE TABLE IF NOT EXISTS hatali_alarmlar (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    icerik TEXT,
                    tip TEXT,
                    orijinal_skor REAL,
                    rapor_tarihi TEXT DEFAULT CURRENT_TIMESTAMP,
                    notlar TEXT
                );

                -- =================================================================
                -- PERFORMANS INDEKSLERI
                -- SQLite tablo taraması (full scan) yerine B-tree lookup yapar.
                -- Yüksek satır sayısında 10-100x hızlanma sağlar.
                -- IF NOT EXISTS sayesinde idempotent → her açılışta güvenle çalışır.
                -- =================================================================

                -- mailler: Auto-sync sırasında her gelen mail için 'bu Gmail ID veritabanında var mı?'
                -- kontrolü yapılıyor (GetAllGmailMessageIds + duplicate temizleme). Bu indeks olmasaydı
                -- O(n) full scan, indeks ile O(log n) lookup.
                CREATE INDEX IF NOT EXISTS idx_mailler_gmail_msg_id ON mailler(gmail_mesaj_id);

                -- mailler: Klasör görüntülerken (Inbox/Sent/Trash...) WHERE klasor_id + ORDER BY tarih DESC
                -- composite indeks ile tek B-tree taramasında hem filtre hem sıralama. En sık kullanılan
                -- sorgu — UI'da her klasör değişiminde tetikleniyor.
                CREATE INDEX IF NOT EXISTS idx_mailler_klasor_tarih ON mailler(klasor_id, tarih DESC);

                -- analiz_loglari: Karantina ve Tüm Loglar panelinde ORDER BY tarih DESC kullanılıyor.
                CREATE INDEX IF NOT EXISTS idx_analiz_loglari_tarih ON analiz_loglari(tarih DESC);

                -- zararli_linkler/ekli_dosyalar: LEFT JOIN ON log_id (GetAnalysisLogs) ve
                -- DELETE WHERE log_id (DeleteAnalysisLog) sorguları için.
                CREATE INDEX IF NOT EXISTS idx_zararli_linkler_log_id ON zararli_linkler(log_id);
                CREATE INDEX IF NOT EXISTS idx_ekli_dosyalar_log_id ON ekli_dosyalar(log_id);

                -- sistem_loglari: Tarih bazlı sorgulama (en yeni loglar üstte).
                CREATE INDEX IF NOT EXISTS idx_sistem_loglari_tarih ON sistem_loglari(islem_tarihi DESC);
            ";
            command.ExecuteNonQuery();

            MigrateDatabase(connection);
            CreateDefaultFolders(connection);
        }

        private static void MigrateDatabase(SqliteConnection connection)
        {
            // mailler tablosu için eski kolonlar (varlık kontrolü yok, ALTER ADD çağırılır, hata olursa zaten var demektir)
            string[] mailColumns = {
                "sql_injection_skoru REAL DEFAULT 0",
                "xss_skoru REAL DEFAULT 0",
                "trojan_skoru REAL DEFAULT 0"
            };
            foreach (var col in mailColumns)
            {
                try
                {
                    var cmd = connection.CreateCommand();
                    cmd.CommandText = $"ALTER TABLE mailler ADD COLUMN {col}";
                    cmd.ExecuteNonQuery();
                }
                catch { /* column already exists */ }
            }

            // zararli_linkler ve ekli_dosyalar tablolarına 'tehdit_tipi' (Trojan/Phishing/Adware vb.)
            // VT TopThreatType() çıktısı buraya yazılacak — eski "Şüpheli/Kritik" generic etiketinin yanında
            // gerçek tehdit kategorisi de saklanır.
            foreach (var table in new[] { "zararli_linkler", "ekli_dosyalar" })
            {
                try
                {
                    var cmd = connection.CreateCommand();
                    cmd.CommandText = $"ALTER TABLE {table} ADD COLUMN tehdit_tipi TEXT DEFAULT ''";
                    cmd.ExecuteNonQuery();
                }
                catch { /* column already exists */ }
            }

            // ekli_dosyalar'a 'dosya_yolu' — manuel tarama sırasında diskteki tam yol.
            // Karantinaya taşıma, yeniden tarama ve "konumu aç" özellikleri için.
            try
            {
                var cmd = connection.CreateCommand();
                cmd.CommandText = "ALTER TABLE ekli_dosyalar ADD COLUMN dosya_yolu TEXT DEFAULT ''";
                cmd.ExecuteNonQuery();
            }
            catch { /* column already exists */ }
        }

        // =====================================================================
        // VERİ MASKELEME (KVKK UYUMLULUĞU — KİŞİSEL VERİLERİN KORUNMASI KANUNU)
        // =====================================================================
        // Veritabanına (analiz_loglari / sistem_loglari / hatali_alarmlar) yazılan
        // mail içeriklerinden kişisel verilerin (PII) maskelenmesi.
        //
        // Maskelenen tipler:
        //   • E-posta adresi
        //   • Türk telefon numarası (0XXX..., +90..., 5XX... formatları)
        //   • TC Kimlik No (11 hane, 1-9 ile başlar — telefondan ayırt edilir)
        //   • Kredi kartı (16 hane; 1234-5678-9012-3456 / 1234 5678 ... varyantları)
        //   • IBAN (TR + 24 hane, opsiyonel boşluklarla)
        //   • Bağlam içinde CVV (CVV: 123)
        //
        // Sıralama önemlidir → daha spesifik desen önce maskelenmeli ki yanlış
        // tip yakalanmasın. Örn: 16 haneli kart, 11 hane TC'den önce işlenir.
        // =====================================================================
        public static string MaskSensitiveData(string text)
        {
            if (string.IsNullOrEmpty(text)) return text;

            // 1) IBAN (TR + 24 hane, opsiyonel boşluk/tire ile) — önce, çünkü içinde
            //    16+ hane sayı kümeleri bulunur, kart desenine takılmasın.
            text = Regex.Replace(
                text,
                @"\bTR\d{2}[\s-]?(?:\d{4}[\s-]?){5}\d{2}\b",
                "[IBAN GİZLENDİ]",
                RegexOptions.IgnoreCase);

            // 2) Kredi kartı — boşluk veya tire ile gruplanmış (1234-5678-9012-3456)
            text = Regex.Replace(
                text,
                @"\b(?:\d{4}[\s-]){3}\d{4}\b",
                "[KART GİZLENDİ]");

            // 3) Kredi kartı — bitişik 16 hane (1234567890123456)
            text = Regex.Replace(text, @"\b\d{16}\b", "[KART GİZLENDİ]");

            // 4) CVV — bağlamlı (CVV/CVC/CV2 ardından 3-4 hane)
            text = Regex.Replace(
                text,
                @"\b(?:CVV|CVC|CV2)[\s:=]*\d{3,4}\b",
                "[CVV GİZLENDİ]",
                RegexOptions.IgnoreCase);

            // 5) E-posta adresi
            text = Regex.Replace(
                text,
                @"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
                "[E-POSTA GİZLENDİ]");

            // 6) Telefon — Türkiye varyantları:
            //    +90 5XX XXX XX XX, 0 5XX XXX XX XX, 5XX XXX XX XX, bitişik 0XXXXXXXXXX
            //    Boşluk ve tire kabul eder. Word boundary ile başka rakamlara yapışmayı engeller.
            text = Regex.Replace(
                text,
                @"(?:\+?90[\s-]?)?0?5\d{2}[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}",
                "[TELEFON GİZLENDİ]");
            // Genel 11-hane 0 ile başlayan (sabit hat dahil)
            text = Regex.Replace(text, @"\b0\d{10}\b", "[TELEFON GİZLENDİ]");

            // 7) TC Kimlik No — 11 hane, 1-9 ile başlar (0 başlamaz, telefondan ayrılır).
            //    Telefon/kart önce maskelendiği için bu noktada güvenle çalışır.
            text = Regex.Replace(text, @"\b[1-9]\d{10}\b", "[TC KİMLİK GİZLENDİ]");

            return text;
        }

        private static void CreateDefaultFolders(SqliteConnection connection)
        {
            var checkCommand = connection.CreateCommand();
            checkCommand.CommandText = "SELECT COUNT(*) FROM klasorler WHERE tip = 'inbox'";
            var count = Convert.ToInt32(checkCommand.ExecuteScalar());

            if (count == 0)
            {
                var insertCommand = connection.CreateCommand();
                insertCommand.CommandText = @"
                    INSERT INTO klasorler (ad, tip) VALUES ('Gelen Kutusu', 'inbox');
                    INSERT INTO klasorler (ad, tip) VALUES ('Giden Kutusu', 'sent');
                    INSERT INTO klasorler (ad, tip) VALUES ('Taslaklar', 'drafts');
                    INSERT INTO klasorler (ad, tip) VALUES ('Çöp Kutusu', 'trash');
                    INSERT INTO klasorler (ad, tip) VALUES ('Spam', 'spam');
                ";
                insertCommand.ExecuteNonQuery();
            }
        }

        public static SqliteConnection GetConnection()
        {
            var connection = new SqliteConnection(ConnectionString);
            connection.Open();
            return connection;
        }

        public static List<Folder> GetFolders()
        {
            var folders = new List<Folder>();
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = "SELECT id, ad, tip FROM klasorler ORDER BY id";

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                folders.Add(new Folder
                {
                    Id = reader.GetInt32(0),
                    Name = reader.GetString(1),
                    Type = reader.GetString(2)
                });
            }
            return folders;
        }

        public static List<Mail> GetMailsByFolder(int folderId, int limit = 500)
        {
            var mails = new List<Mail>();
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = @"
                SELECT id, klasor_id, konu, icerik, gonderen_eposta, alici_eposta, gonderen_ad, tarih,
                       okundu_mu, spam_mi, phishing_mi, phishing_skoru, spam_skoru, ek_var_mi,
                       COALESCE(sql_injection_skoru,0), COALESCE(xss_skoru,0), COALESCE(trojan_skoru,0),
                       gmail_mesaj_id
                FROM mailler
                WHERE klasor_id = @folderId
                ORDER BY tarih DESC
                LIMIT @limit";
            command.Parameters.AddWithValue("@folderId", folderId);
            command.Parameters.AddWithValue("@limit", limit);

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                mails.Add(new Mail
                {
                    Id = reader.GetInt32(0),
                    FolderId = reader.GetInt32(1),
                    Subject = reader.IsDBNull(2) ? "" : reader.GetString(2),
                    Body = reader.IsDBNull(3) ? "" : reader.GetString(3),
                    FromEmail = reader.IsDBNull(4) ? "" : reader.GetString(4),
                    ToEmail = reader.IsDBNull(5) ? "" : reader.GetString(5),
                    FromName = reader.IsDBNull(6) ? "" : reader.GetString(6),
                    Date = reader.IsDBNull(7) ? DateTime.Now : DateTime.Parse(reader.GetString(7)),
                    IsRead = reader.GetInt32(8) == 1,
                    IsSpam = reader.GetInt32(9) == 1,
                    IsPhishing = reader.GetInt32(10) == 1,
                    PhishingScore = reader.IsDBNull(11) ? 0 : reader.GetDouble(11),
                    SpamScore = reader.IsDBNull(12) ? 0 : reader.GetDouble(12),
                    HasAttachments = reader.GetInt32(13) == 1,
                    SqlInjectionScore = reader.GetDouble(14),
                    XssScore = reader.GetDouble(15),
                    TrojanScore = reader.GetDouble(16),
                    GmailMessageId = reader.IsDBNull(17) ? "" : reader.GetString(17)
                });
            }
            return mails;
        }

        public static int InsertMail(Mail mail)
        {
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT INTO mailler (klasor_id, konu, icerik, gonderen_eposta, alici_eposta, gonderen_ad, tarih,
                                   okundu_mu, spam_mi, phishing_mi, phishing_skoru, spam_skoru, ek_var_mi, gmail_mesaj_id,
                                   sql_injection_skoru, xss_skoru, trojan_skoru)
                VALUES (@klasorId, @konu, @icerik, @gonderenEposta, @aliciEposta, @gonderenAd, @tarih,
                        @okunduMu, @spamMi, @phishingMi, @phishingSkoru, @spamSkoru, @ekVarMi, @gmailMesajId,
                        @sqlSkoru, @xssSkoru, @trojanSkoru);
                SELECT last_insert_rowid();";

            command.Parameters.AddWithValue("@klasorId", mail.FolderId);
            command.Parameters.AddWithValue("@konu", mail.Subject ?? "");
            command.Parameters.AddWithValue("@icerik", mail.Body ?? "");
            command.Parameters.AddWithValue("@gonderenEposta", mail.FromEmail ?? "");
            command.Parameters.AddWithValue("@aliciEposta", mail.ToEmail ?? "");
            command.Parameters.AddWithValue("@gonderenAd", mail.FromName ?? "");
            command.Parameters.AddWithValue("@tarih", mail.Date.ToString("yyyy-MM-dd HH:mm:ss"));
            command.Parameters.AddWithValue("@okunduMu", mail.IsRead ? 1 : 0);
            command.Parameters.AddWithValue("@spamMi", mail.IsSpam ? 1 : 0);
            command.Parameters.AddWithValue("@phishingMi", mail.IsPhishing ? 1 : 0);
            command.Parameters.AddWithValue("@phishingSkoru", mail.PhishingScore);
            command.Parameters.AddWithValue("@spamSkoru", mail.SpamScore);
            command.Parameters.AddWithValue("@ekVarMi", mail.HasAttachments ? 1 : 0);
            command.Parameters.AddWithValue("@gmailMesajId", mail.GmailMessageId ?? "");
            command.Parameters.AddWithValue("@sqlSkoru", mail.SqlInjectionScore);
            command.Parameters.AddWithValue("@xssSkoru", mail.XssScore);
            command.Parameters.AddWithValue("@trojanSkoru", mail.TrojanScore);

            return Convert.ToInt32(command.ExecuteScalar());
        }

        public static void UpdateMail(Mail mail)
        {
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = @"
                UPDATE mailler SET
                    konu = @konu, icerik = @icerik, gonderen_eposta = @gonderenEposta, alici_eposta = @aliciEposta,
                    gonderen_ad = @gonderenAd, okundu_mu = @okunduMu, spam_mi = @spamMi, phishing_mi = @phishingMi,
                    phishing_skoru = @phishingSkoru, spam_skoru = @spamSkoru, ek_var_mi = @ekVarMi,
                    sql_injection_skoru = @sqlSkoru, xss_skoru = @xssSkoru, trojan_skoru = @trojanSkoru
                WHERE id = @id";

            command.Parameters.AddWithValue("@id", mail.Id);
            command.Parameters.AddWithValue("@konu", mail.Subject ?? "");
            command.Parameters.AddWithValue("@icerik", mail.Body ?? "");
            command.Parameters.AddWithValue("@gonderenEposta", mail.FromEmail ?? "");
            command.Parameters.AddWithValue("@aliciEposta", mail.ToEmail ?? "");
            command.Parameters.AddWithValue("@gonderenAd", mail.FromName ?? "");
            command.Parameters.AddWithValue("@okunduMu", mail.IsRead ? 1 : 0);
            command.Parameters.AddWithValue("@spamMi", mail.IsSpam ? 1 : 0);
            command.Parameters.AddWithValue("@phishingMi", mail.IsPhishing ? 1 : 0);
            command.Parameters.AddWithValue("@phishingSkoru", mail.PhishingScore);
            command.Parameters.AddWithValue("@spamSkoru", mail.SpamScore);
            command.Parameters.AddWithValue("@ekVarMi", mail.HasAttachments ? 1 : 0);
            command.Parameters.AddWithValue("@sqlSkoru", mail.SqlInjectionScore);
            command.Parameters.AddWithValue("@xssSkoru", mail.XssScore);
            command.Parameters.AddWithValue("@trojanSkoru", mail.TrojanScore);

            command.ExecuteNonQuery();
        }

        public static void DeleteMail(int mailId)
        {
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM mailler WHERE id = @id";
            command.Parameters.AddWithValue("@id", mailId);
            command.ExecuteNonQuery();
        }

        public static void MoveMail(int mailId, int targetFolderId)
        {
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = "UPDATE mailler SET klasor_id = @folderId WHERE id = @id";
            command.Parameters.AddWithValue("@folderId", targetFolderId);
            command.Parameters.AddWithValue("@id", mailId);
            command.ExecuteNonQuery();
        }

        public static async Task<List<Folder>> GetFoldersAsync()
        {
            return await Task.Run(() => GetFolders());
        }

        public static async Task<List<Mail>> GetMailsByFolderAsync(int folderId, int limit = 50)
        {
            return await Task.Run(() => GetMailsByFolder(folderId, limit));
        }

        public static async Task<int> InsertMailAsync(Mail mail)
        {
            return await Task.Run(() => InsertMail(mail));
        }

        public static async Task UpdateMailAsync(Mail mail)
        {
            await Task.Run(() => UpdateMail(mail));
        }

        public static async Task DeleteMailAsync(int mailId)
        {
            await Task.Run(() => DeleteMail(mailId));
        }

        public static async Task MoveMailAsync(int mailId, int targetFolderId)
        {
            await Task.Run(() => MoveMail(mailId, targetFolderId));
        }

        public static void SaveGmailAccount(string email, string appPassword)
        {
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT OR REPLACE INTO gmail_hesaplari (eposta, uygulama_sifresi, son_senkronizasyon)
                VALUES (@email, @appPassword, @lastSync)";

            command.Parameters.AddWithValue("@email", email);
            // Parola DPAPI ile şifrelenerek saklanır (yalnızca aynı Windows kullanıcı çözer).
            command.Parameters.AddWithValue("@appPassword", SecureStore.Encrypt(appPassword));
            command.Parameters.AddWithValue("@lastSync", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            command.ExecuteNonQuery();
        }

        public static (string? email, string? password) GetGmailAccount()
        {
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = "SELECT eposta, uygulama_sifresi FROM gmail_hesaplari LIMIT 1";

            string? email = null;
            string? storedPassword = null;
            using (var reader = command.ExecuteReader())
            {
                if (reader.Read())
                {
                    email = reader.GetString(0);
                    storedPassword = reader.GetString(1);
                }
            } // reader kapanır — UPDATE'i güvenle çalıştırabiliriz

            if (email == null || storedPassword == null)
                return (null, null);

            string decrypted = SecureStore.Decrypt(storedPassword);

            // Migration: eski (düz metin) kayıt → DPAPI ile yeniden yaz
            if (!SecureStore.IsEncrypted(storedPassword) && !string.IsNullOrEmpty(decrypted))
            {
                try
                {
                    var migrateCmd = connection.CreateCommand();
                    migrateCmd.CommandText = "UPDATE gmail_hesaplari SET uygulama_sifresi = @enc WHERE eposta = @email";
                    migrateCmd.Parameters.AddWithValue("@enc", SecureStore.Encrypt(decrypted));
                    migrateCmd.Parameters.AddWithValue("@email", email);
                    migrateCmd.ExecuteNonQuery();
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"DPAPI migration failed (non-fatal): {ex.Message}");
                }
            }

            return (email, decrypted);
        }

        /// <summary>
        /// Veritabanındaki TÜM mailler için (hangi klasörde olursa olsun) Gmail Message-ID'leri
        /// döndürür. Auto-sync sırasında duplikat eklemeyi engellemek için kullanılır.
        /// Inbox'tan trash'e taşınmış mailler de bu set'te olur ki tekrar import edilmesin.
        /// </summary>
        public static HashSet<string> GetAllGmailMessageIds()
        {
            var ids = new HashSet<string>();
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = "SELECT DISTINCT gmail_mesaj_id FROM mailler WHERE gmail_mesaj_id IS NOT NULL AND gmail_mesaj_id != ''";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                ids.Add(reader.GetString(0));
            }
            return ids;
        }

        public static async Task<HashSet<string>> GetAllGmailMessageIdsAsync()
        {
            return await Task.Run(() => GetAllGmailMessageIds());
        }

        /// <summary>
        /// Aynı gmail_mesaj_id'ye sahip duplikat kayıtları temizler — en eski (en küçük id)
        /// olanı tutar, diğerlerini siler. Tek seferlik migration için (mevcut bozuk DB'yi temizler).
        /// </summary>
        public static int RemoveDuplicateMails()
        {
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = @"
                DELETE FROM mailler
                WHERE gmail_mesaj_id IS NOT NULL
                  AND gmail_mesaj_id != ''
                  AND id NOT IN (
                      SELECT MIN(id) FROM mailler
                      WHERE gmail_mesaj_id IS NOT NULL AND gmail_mesaj_id != ''
                      GROUP BY gmail_mesaj_id
                  )";
            return command.ExecuteNonQuery();
        }

        public static void DeleteGmailAccount()
        {
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM gmail_hesaplari";
            command.ExecuteNonQuery();
        }

        public static void UpdateGmailSyncTime()
        {
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = "UPDATE gmail_hesaplari SET son_senkronizasyon = @lastSync";
            command.Parameters.AddWithValue("@lastSync", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            command.ExecuteNonQuery();
        }

        public static List<Mail> SearchMails(string query)
        {
            var mails = new List<Mail>();
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = @"
                SELECT id, klasor_id, konu, icerik, gonderen_eposta, alici_eposta, gonderen_ad, tarih,
                       okundu_mu, spam_mi, phishing_mi, phishing_skoru, spam_skoru, ek_var_mi,
                       COALESCE(sql_injection_skoru,0), COALESCE(xss_skoru,0), COALESCE(trojan_skoru,0),
                       gmail_mesaj_id
                FROM mailler
                WHERE konu LIKE @query OR icerik LIKE @query OR gonderen_eposta LIKE @query
                ORDER BY tarih DESC
                LIMIT 500";
            command.Parameters.AddWithValue("@query", $"%{query}%");

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                mails.Add(new Mail
                {
                    Id = reader.GetInt32(0),
                    FolderId = reader.GetInt32(1),
                    Subject = reader.IsDBNull(2) ? "" : reader.GetString(2),
                    Body = reader.IsDBNull(3) ? "" : reader.GetString(3),
                    FromEmail = reader.IsDBNull(4) ? "" : reader.GetString(4),
                    ToEmail = reader.IsDBNull(5) ? "" : reader.GetString(5),
                    FromName = reader.IsDBNull(6) ? "" : reader.GetString(6),
                    Date = reader.IsDBNull(7) ? DateTime.Now : DateTime.Parse(reader.GetString(7)),
                    IsRead = reader.GetInt32(8) == 1,
                    IsSpam = reader.GetInt32(9) == 1,
                    IsPhishing = reader.GetInt32(10) == 1,
                    PhishingScore = reader.IsDBNull(11) ? 0 : reader.GetDouble(11),
                    SpamScore = reader.IsDBNull(12) ? 0 : reader.GetDouble(12),
                    HasAttachments = reader.GetInt32(13) == 1,
                    SqlInjectionScore = reader.GetDouble(14),
                    XssScore = reader.GetDouble(15),
                    TrojanScore = reader.GetDouble(16),
                    GmailMessageId = reader.IsDBNull(17) ? "" : reader.GetString(17)
                });
            }
            return mails;
        }

        public static List<AnalysisLog> GetAnalysisLogs()
        {
            var logs = new List<AnalysisLog>();
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            // LEFT JOIN ile zararli_linkler ve ekli_dosyalar tablolarından tehdit_tipi de alınır.
            // COALESCE: önce URL kaydındakine bak, sonra dosya kaydı, ikisi de yoksa boş.
            // En son 10 kayıt.
            command.CommandText = @"
                SELECT al.id, al.tarih, al.tip, al.islenen_metin, al.skor, al.sonuc,
                       COALESCE(zl.tehdit_tipi, ed.tehdit_tipi, '') AS tehdit_tipi
                FROM analiz_loglari al
                LEFT JOIN zararli_linkler zl ON zl.log_id = al.id
                LEFT JOIN ekli_dosyalar ed ON ed.log_id = al.id
                ORDER BY al.tarih DESC
                LIMIT 10";

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                logs.Add(new AnalysisLog
                {
                    Id = reader.GetInt32(0),
                    Date = reader.IsDBNull(1) ? "" : reader.GetString(1),
                    Type = reader.IsDBNull(2) ? "" : reader.GetString(2),
                    Content = reader.IsDBNull(3) ? "" : reader.GetString(3),
                    Score = reader.IsDBNull(4) ? 0 : reader.GetDouble(4),
                    Result = reader.IsDBNull(5) ? "" : reader.GetString(5),
                    ThreatType = reader.IsDBNull(6) ? "" : reader.GetString(6)
                });
            }
            return logs;
        }

        /// <summary>
        /// Tüm analiz loglarını ve bağlı zararli_linkler/ekli_dosyalar kayıtlarını siler.
        /// Karantina + Tüm Loglar tek seferde temizlenir. Foreign key tutarlılığı için
        /// önce alt tablolar, sonra ana tablo silinir.
        /// </summary>
        public static int ClearAllAnalysisLogs()
        {
            using var connection = GetConnection();
            using var transaction = connection.BeginTransaction();

            var cmd1 = connection.CreateCommand();
            cmd1.Transaction = transaction;
            cmd1.CommandText = "DELETE FROM zararli_linkler";
            cmd1.ExecuteNonQuery();

            var cmd2 = connection.CreateCommand();
            cmd2.Transaction = transaction;
            cmd2.CommandText = "DELETE FROM ekli_dosyalar";
            cmd2.ExecuteNonQuery();

            var cmd3 = connection.CreateCommand();
            cmd3.Transaction = transaction;
            cmd3.CommandText = "DELETE FROM analiz_loglari";
            int removed = cmd3.ExecuteNonQuery();

            transaction.Commit();
            return removed;
        }

        public static async Task<int> ClearAllAnalysisLogsAsync()
        {
            return await Task.Run(() => ClearAllAnalysisLogs());
        }

        /// <summary>
        /// Bir analiz logunu siler. SQLite'ta tablolar ON DELETE CASCADE OLMADAN tanımlandığı için
        /// ve foreign_keys=ON olduğu için, doğrudan parent silmek FK ihlali fırlatır.
        /// Bu metot transaction içinde önce alt tabloları (zararli_linkler, ekli_dosyalar) siler,
        /// sonra ana logu siler — uygulama seviyesinde CASCADE davranışı.
        /// </summary>
        public static void DeleteAnalysisLog(int logId)
        {
            using var connection = GetConnection();
            using var transaction = connection.BeginTransaction();

            // 1) zararli_linkler'deki child kayıtlar
            var cmd1 = connection.CreateCommand();
            cmd1.Transaction = transaction;
            cmd1.CommandText = "DELETE FROM zararli_linkler WHERE log_id = @id";
            cmd1.Parameters.AddWithValue("@id", logId);
            cmd1.ExecuteNonQuery();

            // 2) ekli_dosyalar'daki child kayıtlar
            var cmd2 = connection.CreateCommand();
            cmd2.Transaction = transaction;
            cmd2.CommandText = "DELETE FROM ekli_dosyalar WHERE log_id = @id";
            cmd2.Parameters.AddWithValue("@id", logId);
            cmd2.ExecuteNonQuery();

            // 3) Şimdi parent log güvenle silinebilir
            var cmd3 = connection.CreateCommand();
            cmd3.Transaction = transaction;
            cmd3.CommandText = "DELETE FROM analiz_loglari WHERE id = @id";
            cmd3.Parameters.AddWithValue("@id", logId);
            cmd3.ExecuteNonQuery();

            transaction.Commit();
        }

        public static async Task DeleteAnalysisLogAsync(int logId)
        {
            await Task.Run(() => DeleteAnalysisLog(logId));
        }

        public static async Task<List<Mail>> SearchMailsAsync(string query)
        {
            return await Task.Run(() => SearchMails(query));
        }

        public static async Task<List<AnalysisLog>> GetAnalysisLogsAsync()
        {
            return await Task.Run(() => GetAnalysisLogs());
        }

        public static int SaveAnalysisLog(string content, string type, double score, string result, string? sender = null, string? subject = null)
        {
            string maskedContent = MaskSensitiveData(content);

            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT INTO analiz_loglari (islenen_metin, tip, skor, sonuc, gonderen_adres, konu, tarih)
                VALUES (@content, @type, @score, @result, @sender, @subject, @date);
                SELECT last_insert_rowid();";

            command.Parameters.AddWithValue("@content", maskedContent.Length > 200 ? maskedContent.Substring(0, 200) : maskedContent);
            command.Parameters.AddWithValue("@type", type);
            command.Parameters.AddWithValue("@score", score);
            command.Parameters.AddWithValue("@result", result);
            command.Parameters.AddWithValue("@sender", sender ?? (object)DBNull.Value);
            command.Parameters.AddWithValue("@subject", subject ?? (object)DBNull.Value);
            command.Parameters.AddWithValue("@date", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));

            int logId = Convert.ToInt32(command.ExecuteScalar());

            SaveSystemLog("Yapay Zeka Analizi", $"Analiz tamamlandı. Skor: {score}, Sonuç: {result}");

            return logId;
        }

        /// <summary>
        /// URL taraması Şüpheli/Kritik olduğunda zararli_linkler'e kayıt ekler.
        /// vtDurumu: "Şüpheli" | "Kritik" (genel seviye)
        /// tehditTipi: "Trojan" | "Phishing" | "Malware" | "Adware" vb. (VT vendor sonucundan tip)
        /// </summary>
        public static void SaveMaliciousLink(int logId, string urlAdresi, string vtDurumu, string tehditTipi = "")
        {
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT INTO zararli_linkler (log_id, url_adresi, domain, virustotal_durumu, tehdit_tipi)
                VALUES (@logId, @url, @domain, @durum, @tip)";

            // Domain çıkarma — bozuk URL'lerde sessiz boş bırak
            string domain = "";
            try
            {
                if (Uri.TryCreate(urlAdresi, UriKind.Absolute, out Uri? uri))
                    domain = uri.Host;
            }
            catch { }

            command.Parameters.AddWithValue("@logId", logId);
            command.Parameters.AddWithValue("@url", urlAdresi ?? "");
            command.Parameters.AddWithValue("@domain", domain);
            command.Parameters.AddWithValue("@durum", vtDurumu ?? "");
            command.Parameters.AddWithValue("@tip", tehditTipi ?? "");
            command.ExecuteNonQuery();
        }

        public static async Task SaveMaliciousLinkAsync(int logId, string urlAdresi, string vtDurumu, string tehditTipi = "")
        {
            await Task.Run(() => SaveMaliciousLink(logId, urlAdresi, vtDurumu, tehditTipi));
        }

        /// <summary>
        /// Dosya taraması Şüpheli/Kritik olduğunda ekli_dosyalar'a kayıt ekler.
        /// virustotalSkoru: Malicious motor sayısı (kaç AV zararlı dedi).
        /// tehditTipi: "Trojan", "Backdoor", "Spyware", "Ransomware" vb. (VT vendor sonucundan).
        /// dosyaYolu: diskteki tam yol (manuel tarama için; konumu aç / yeniden tara için kullanılır).
        /// </summary>
        public static void SaveAttachedFile(int logId, string dosyaAdi, string dosyaHash, int virustotalSkoru, string tehditTipi = "", string dosyaYolu = "")
        {
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT INTO ekli_dosyalar (log_id, dosya_adi, dosya_hash, virustotal_skoru, tehdit_tipi, dosya_yolu)
                VALUES (@logId, @ad, @hash, @skor, @tip, @yol)";

            command.Parameters.AddWithValue("@logId", logId);
            command.Parameters.AddWithValue("@ad", dosyaAdi ?? "");
            command.Parameters.AddWithValue("@hash", dosyaHash ?? "");
            command.Parameters.AddWithValue("@skor", virustotalSkoru);
            command.Parameters.AddWithValue("@tip", tehditTipi ?? "");
            command.Parameters.AddWithValue("@yol", dosyaYolu ?? "");
            command.ExecuteNonQuery();
        }

        public static async Task SaveAttachedFileAsync(int logId, string dosyaAdi, string dosyaHash, int virustotalSkoru, string tehditTipi = "", string dosyaYolu = "")
        {
            await Task.Run(() => SaveAttachedFile(logId, dosyaAdi, dosyaHash, virustotalSkoru, tehditTipi, dosyaYolu));
        }

        public static void SaveSystemLog(string type, string detail)
        {
            // KVKK: Sistem loglarına yazılan detay metinleri (genelde mail konusu / gönderici)
            // PII içerebilir → maskele.
            string maskedDetail = MaskSensitiveData(detail ?? "");

            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = "INSERT INTO sistem_loglari (islem_tipi, islem_detayi) VALUES (@type, @detail)";
            command.Parameters.AddWithValue("@type", type);
            command.Parameters.AddWithValue("@detail", maskedDetail);
            command.ExecuteNonQuery();
        }

        public static void SaveSetting(string key, string value)
        {
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = "INSERT OR REPLACE INTO ayarlar (anahtar, deger) VALUES (@key, @value)";
            command.Parameters.AddWithValue("@key", key);
            command.Parameters.AddWithValue("@value", value);
            command.ExecuteNonQuery();
        }

        public static string? GetSetting(string key)
        {
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = "SELECT deger FROM ayarlar WHERE anahtar = @key";
            command.Parameters.AddWithValue("@key", key);

            var result = command.ExecuteScalar();
            return result?.ToString();
        }

        // ==========================================
        // ŞÜPHELİ GÖNDERİCİLER (Kullanıcı tarafından işaretlenen)
        // ==========================================

        /// <summary>
        /// Bir gönderici e-postasını şüpheli listesine ekler.
        /// UNIQUE constraint ile aynı e-posta tekrar eklenemez (INSERT OR IGNORE).
        /// </summary>
        public static void AddSuspiciousSender(string email, string notlar = "")
        {
            if (string.IsNullOrWhiteSpace(email)) return;
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT OR IGNORE INTO supheli_gondericiler (eposta, notlar)
                VALUES (@email, @notes)";
            command.Parameters.AddWithValue("@email", email.ToLowerInvariant().Trim());
            command.Parameters.AddWithValue("@notes", notlar ?? "");
            command.ExecuteNonQuery();
        }

        public static void RemoveSuspiciousSender(string email)
        {
            if (string.IsNullOrWhiteSpace(email)) return;
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM supheli_gondericiler WHERE LOWER(eposta) = LOWER(@email)";
            command.Parameters.AddWithValue("@email", email.Trim());
            command.ExecuteNonQuery();
        }

        public static List<SuspiciousSender> GetSuspiciousSenders()
        {
            var list = new List<SuspiciousSender>();
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = "SELECT id, eposta, eklenme_tarihi, notlar FROM supheli_gondericiler ORDER BY eklenme_tarihi DESC";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                list.Add(new SuspiciousSender
                {
                    Id = reader.GetInt32(0),
                    Email = reader.GetString(1),
                    DateAdded = reader.IsDBNull(2) ? "" : reader.GetString(2),
                    Notes = reader.IsDBNull(3) ? "" : reader.GetString(3)
                });
            }
            return list;
        }

        public static async Task<List<SuspiciousSender>> GetSuspiciousSendersAsync()
        {
            return await Task.Run(() => GetSuspiciousSenders());
        }

        /// <summary>
        /// Sync sırasında her mail için tek tek DB sorgusu yapmak yerine listeyi bir kerede
        /// HashSet olarak al — O(1) lookup.
        /// </summary>
        public static HashSet<string> GetSuspiciousSenderEmails()
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = "SELECT eposta FROM supheli_gondericiler";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                set.Add(reader.GetString(0));
            }
            return set;
        }

        public static bool IsSenderSuspicious(string email)
        {
            if (string.IsNullOrWhiteSpace(email)) return false;
            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = "SELECT COUNT(*) FROM supheli_gondericiler WHERE LOWER(eposta) = LOWER(@email)";
            command.Parameters.AddWithValue("@email", email.Trim());
            return Convert.ToInt32(command.ExecuteScalar()) > 0;
        }

        public static void SaveFalsePositive(string content, string type, double originalScore, string notes = "")
        {
            // KVKK: Kullanıcının "yanlış alarm" olarak işaretlediği mail içeriği DB'ye yazılıyor.
            // İçerik ve notlar PII içerebilir → maskele.
            string maskedContent = MaskSensitiveData(content ?? "");
            string maskedNotes = MaskSensitiveData(notes ?? "");
            if (maskedContent.Length > 500) maskedContent = maskedContent.Substring(0, 500);

            using var connection = GetConnection();
            var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT INTO hatali_alarmlar (icerik, tip, orijinal_skor, notlar, rapor_tarihi)
                VALUES (@content, @type, @originalScore, @notes, @reportedAt)";

            command.Parameters.AddWithValue("@content", maskedContent);
            command.Parameters.AddWithValue("@type", type);
            command.Parameters.AddWithValue("@originalScore", originalScore);
            command.Parameters.AddWithValue("@notes", maskedNotes);
            command.Parameters.AddWithValue("@reportedAt", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));

            command.ExecuteNonQuery();
        }
    }

    // --- MODELLER ---
    // UI tarafı çökmesin diye C# Property (değişken) isimlerini İngilizce bıraktık,
    // Sadece SQL sorguları içindeki veritabanı yansımaları Türkçe oldu.

    public class AnalysisLog
    {
        public int Id { get; set; }
        public string Date { get; set; } = "";
        public string Type { get; set; } = "";
        public string Content { get; set; } = "";
        public double Score { get; set; }
        public string Result { get; set; } = "";
        public string SenderAddress { get; set; } = "";
        public string Subject { get; set; } = "";

        // zararli_linkler.tehdit_tipi VEYA ekli_dosyalar.tehdit_tipi'nden gelir
        // (LEFT JOIN ile çekilir). Örn: "Trojan", "Phishing", "Adware". Boş ise tip belirlenmemiş.
        public string ThreatType { get; set; } = "";
    }

    /// <summary>
    /// Kullanıcının manuel olarak şüpheli işaretlediği bir mail göndericisi.
    /// Bu listedeki adreslerden gelen mailler sync sırasında otomatik Çöp Kutusu'na taşınır.
    /// </summary>
    public class SuspiciousSender
    {
        public int Id { get; set; }
        public string Email { get; set; } = "";
        public string DateAdded { get; set; } = "";
        public string Notes { get; set; } = "";
    }

    public class SystemLog
    {
        public int Id { get; set; }
        public string ActionType { get; set; } = "";
        public string ActionDetail { get; set; } = "";
        public string ActionDate { get; set; } = "";
    }

    public class Folder
    {
        public int Id { get; set; }
        public string Name { get; set; } = "";
        public string Type { get; set; } = "";
    }

    public class Mail
    {
        public int Id { get; set; }
        public int FolderId { get; set; }
        public string Subject { get; set; } = "";
        public string Body { get; set; } = "";
        public string FromEmail { get; set; } = "";
        public string ToEmail { get; set; } = "";
        public string FromName { get; set; } = "";
        public DateTime Date { get; set; }
        public bool IsRead { get; set; }
        public bool IsSpam { get; set; }
        public bool IsPhishing { get; set; }
        public double PhishingScore { get; set; }
        public double SpamScore { get; set; }
        public double SqlInjectionScore { get; set; }
        public double XssScore { get; set; }
        public double TrojanScore { get; set; }
        public bool HasAttachments { get; set; }
        public string GmailMessageId { get; set; } = "";

        // ==========================================
        // TEHDIT ETİKETİ (mail listesi gösterimi için)
        // En yüksek skorlu tehdit kategorisi ≥40 ise etiket gösterilir.
        // Analysis panel cards ile aynı renk paleti.
        // ==========================================
        public string ThreatBadgeLabel
        {
            get
            {
                double top = 0;
                string label = "";
                if (PhishingScore > top)     { top = PhishingScore;     label = "Phishing"; }
                if (SqlInjectionScore > top) { top = SqlInjectionScore; label = "SQL Injection"; }
                if (XssScore > top)          { top = XssScore;          label = "XSS"; }
                if (TrojanScore > top)       { top = TrojanScore;       label = "Trojan"; }
                if (SpamScore > top)         { top = SpamScore;         label = "Spam"; }
                return top >= 40 ? label : "";
            }
        }

        /// <summary>WPF Binding için doğrudan Brush — String'i parse etmeye gerek kalmaz.</summary>
        public System.Windows.Media.Brush ThreatBadgeBrush
        {
            get
            {
                string hex = ThreatBadgeLabel switch
                {
                    "Phishing"      => "#EF4444",
                    "Spam"          => "#F59E0B",
                    "SQL Injection" => "#A855F7",
                    "XSS"           => "#EC4899",
                    "Trojan"        => "#6366F1",
                    _ => "#A0A0A0"
                };
                var color = (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(hex);
                return new System.Windows.Media.SolidColorBrush(color);
            }
        }

        public bool HasThreatBadge => !string.IsNullOrEmpty(ThreatBadgeLabel);

        public Visibility ThreatBadgeVisibility => HasThreatBadge ? Visibility.Visible : Visibility.Collapsed;
    }
}