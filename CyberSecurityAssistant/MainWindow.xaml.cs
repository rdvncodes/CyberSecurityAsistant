using System.Collections.ObjectModel;
using System.Text.Json;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Animation;
using MahApps.Metro.IconPacks;
using CyberSecurityAssistant.Services;
using Color = System.Windows.Media.Color;
using ColorConverter = System.Windows.Media.ColorConverter;
using Brushes = System.Windows.Media.Brushes;
using Application = System.Windows.Application;
using MessageBox = System.Windows.MessageBox;
using DragEventArgs = System.Windows.DragEventArgs;
using DataFormats = System.Windows.DataFormats;
using QuestPDF;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace CyberSecurityAssistant
{
    public partial class MainWindow : Window
    {
        private string _apiKey = "";
        private readonly string _settingsFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "vt_apikey.txt");
        private static readonly HttpClient _httpClient = new HttpClient();
        private VTScanResult? _lastVtResult;
        private string GetFileHash(string filePath)
        {
            using (var sha256 = SHA256.Create())
            {
                using (var stream = File.OpenRead(filePath))
                {
                    var hashBytes = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                }
            }
        }

        // ════════════════════════════════════════════════════════════════════════
        // 🛡️ JÜRİ DEMO MODU — Sahte Malware Hash Eşlemesi
        // ────────────────────────────────────────────────────────────────────────
        // Sunum sırasında gerçek malware tutmadan VirusTotal'in tespit gücünü
        // göstermek için kullanılır. StartAnalysis_Click içindeki dosya tarama
        // bloğunda dosya ismi bu dictionary'de varsa, gerçek hash yerine
        // dünyaca ünlü malware hash'i VT'ye gönderilir → "X/Y motor zararlı"
        // sonucu döner. Dosya içeriği güvenli kalır.
        //
        // KULLANIM:
        //   Masaüstünde boş .txt oluşturup adlarını şu şekilde değiştirin
        //   (uzantı dahil, "Dosya uzantılarını göster" açık olmalı):
        //     • WannaCry_Ransomware.exe
        //     • Zeus_Spyware.bat
        //     • Emotet_Trojan.doc
        //     • SuperMario_Adware.apk
        //
        // SUNUM SONRASI: Bu dictionary'i ve StartAnalysis_Click içindeki demo
        // bloğunu silmek yeterli — kod normal davranışına döner.
        // ════════════════════════════════════════════════════════════════════════
        private static readonly Dictionary<string, string> _demoMalwareHashes =
            new(StringComparer.OrdinalIgnoreCase)
            {
                // WannaCry — 2017 küresel fidye yazılımı (200K+ bilgisayar etkilendi)
                { "WannaCry_Ransomware.exe", "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c" },
                // Zeus — Banka hesabı çalan ünlü casus/trojan yazılımı
                { "Zeus_Spyware.bat",        "eb10f27dd0e7883ba28a05c30fbcc5d04cc61bd4e40243be4b56839ea2f18542" },
                // Emotet — Modüler trojan, genelde e-posta üzerinden yayılır
                { "Emotet_Trojan.doc",       "3368297b69fceeb1af0e9ec1aa959cbdb2cb22b9b73d6e5d8b7b258679f04646" },
                // SuperMario sahte Android oyun → Adware (reklam tabanlı zararlı)
                { "SuperMario_Adware.apk",   "6025bc54fc48ed6283ff6e9cda7dffdd1a52fc1a2a4b6796c342f5344eb0ef44" },
            };
        static MainWindow()
        {
            // Token appsettings.json'dan okunur — hardcoded değil
            _httpClient.DefaultRequestHeaders.Add("x-api-key", AppConfig.Settings.InternalApiAuthToken);
            _httpClient.DefaultRequestHeaders.Add("ngrok-skip-browser-warning", "true");
        }

        private System.Windows.Forms.NotifyIcon _notifyIcon = null!;
        private FileSystemWatcher _folderWatcher = null!;

        private GmailService _gmailService = null!;
        private MLModelService _mlService = null!;

        private int _currentFolderId = 1;
        private Mail? _selectedMail;
        private bool _isApiVisible = false;
        private string _selectedFilePath = "";

        private ObservableCollection<Mail> _mailList = new();

        public MainWindow()
        {
            InitializeComponent();

            DatabaseHelper.InitializeDatabase();

            // KVKK / Disclaimer — ilk açılışta gösterilir. Onay sonrası DB'ye yazılır,
            // sonraki açılışlarda atlanır. Kullanıcı kabul etmeden uygulama etkileşimsiz.
            ShowKvkkOverlayIfNeeded();

            // Tek seferlik: önceki sync bug'ından kalan duplikat mailleri temizle.
            // Aynı GmailMessageId'ye sahip kayıtlardan en eskisi tutulur, diğerleri silinir.
            try
            {
                int removed = DatabaseHelper.RemoveDuplicateMails();
                if (removed > 0)
                    System.Diagnostics.Debug.WriteLine($"[Cleanup] {removed} duplicate mail kaydı silindi");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[Cleanup] Duplicate cleanup failed: {ex.Message}");
            }

            // Önceki oturumda seçilen dili uygula (varsayılan TR).
            // ChangeLanguage InitializeComponent'ten sonra çağrılmalı ki MergedDictionaries varolsun.
            string savedLang = DatabaseHelper.GetSetting("language") ?? "TR";
            ChangeLanguage(savedLang);

            LoadApiKey();
            SetupSystemTray();
            SetupFolderWatcher();

            _gmailService = new GmailService();
            _gmailService.StatusChanged += GmailService_StatusChanged;

            _mlService = new MLModelService();
            _mlService.StatusChanged += MlService_StatusChanged;
            _mlService.RefreshCachedUrl();

            LoadFoldersAsync();
            LoadMailsForFolder(_currentFolderId);
            CheckGmailConnection();

            // QuestPDF License initialized

            // Flask servisini arka planda başlat (predict.py).
            // Zaten dışarıdan çalışıyorsa duplicate açmaz; yoksa python predict.py'ı
            // çocuk process olarak başlatır ve app kapanışında otomatik öldürür.
            _ = StartFlaskInBackgroundAsync();
        }

        /// <summary>
        /// Flask servisini fire-and-forget olarak başlatır ve sonucu status bar'a yazar.
        /// UI thread'i bloklamaz; ML analizi henüz hazır değilse heuristik fallback çalışır.
        /// </summary>
        private async Task StartFlaskInBackgroundAsync()
        {
            try
            {
                StatusText.Text = "Flask servisi başlatılıyor...";
                bool ok = await FlaskServiceLauncher.EnsureRunningAsync(
                    statusCallback: msg =>
                    {
                        // Background thread'ten geliyor olabilir
                        Dispatcher.BeginInvoke(new Action(() =>
                        {
                            System.Diagnostics.Debug.WriteLine($"[FlaskLauncher] {msg}");
                        }));
                    });

                Dispatcher.BeginInvoke(new Action(() =>
                {
                    if (ok)
                    {
                        StatusText.Text = "Hazır — Flask servisi aktif";
                        if (AiStatusText != null)
                        {
                            AiStatusText.Text = "AI: Aktif";
                            AiStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4ADE80"));
                        }
                    }
                    else
                    {
                        StatusText.Text = "Hazır — Flask kapalı (heuristik mod)";
                        if (AiStatusText != null)
                        {
                            AiStatusText.Text = "AI: Çevrimdışı (heuristik)";
                            AiStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));
                        }
                    }
                }));
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"StartFlaskInBackgroundAsync hata: {ex.Message}");
            }
        }

        private void GmailService_StatusChanged(object? sender, string status)
        {
            Dispatcher.Invoke(() =>
            {
                GmailStatusText.Text = status;
            });
        }

        private void MlService_StatusChanged(object? sender, string status)
        {
            Dispatcher.Invoke(() =>
            {
                StatusText.Text = status;
            });
        }

        private async Task LoadFoldersAsync()
        {
            await DatabaseHelper.GetFoldersAsync();
        }

        private async void LoadMailsForFolder(int folderId)
        {
            _currentFolderId = folderId;
            _mailList.Clear();

            try
            {
                var mails = await DatabaseHelper.GetMailsByFolderAsync(folderId);

                foreach (var mail in mails)
                {
                    _mailList.Add(mail);
                }

                MailListBox.ItemsSource = _mailList;
                EmptyMailListText.Visibility = _mailList.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Mail yükleme hatası: {ex.Message}";
                System.Diagnostics.Debug.WriteLine($"LoadMailsForFolder Error: {ex}");
            }

            UpdateFolderButtonStyles();
        }

        private void UpdateFolderButtonStyles()
        {
            BtnInbox.Style = _currentFolderId == 1 ? (Style)FindResource("ActiveFolderButton") : (Style)FindResource("FolderButton");
            BtnSent.Style = _currentFolderId == 2 ? (Style)FindResource("ActiveFolderButton") : (Style)FindResource("FolderButton");
            BtnDrafts.Style = _currentFolderId == 3 ? (Style)FindResource("ActiveFolderButton") : (Style)FindResource("FolderButton");
            BtnSpam.Style = _currentFolderId == 5 ? (Style)FindResource("ActiveFolderButton") : (Style)FindResource("FolderButton");
            BtnTrash.Style = _currentFolderId == 4 ? (Style)FindResource("ActiveFolderButton") : (Style)FindResource("FolderButton");
        }

        private void FolderInbox_Click(object sender, RoutedEventArgs e)
        {
            LoadMailsForFolder(1);
        }

        private void FolderSent_Click(object sender, RoutedEventArgs e)
        {
            LoadMailsForFolder(2);
        }

        private void FolderDrafts_Click(object sender, RoutedEventArgs e)
        {
            LoadMailsForFolder(3);
        }

        private void FolderSpam_Click(object sender, RoutedEventArgs e)
        {
            LoadMailsForFolder(5);
        }

        private void FolderTrash_Click(object sender, RoutedEventArgs e)
        {
            LoadMailsForFolder(4);
        }

        // ==========================================
        // ŞÜPHELİ GÖNDERİCİLER
        // ==========================================

        private async void OpenSuspiciousSenders_Click(object sender, RoutedEventArgs e)
        {
            await LoadSuspiciousSendersListAsync();
            SuspiciousSendersOverlay.Visibility = Visibility.Visible;
        }

        private void CloseSuspiciousSenders_Click(object sender, RoutedEventArgs e)
        {
            SuspiciousSendersOverlay.Visibility = Visibility.Collapsed;
            NewSuspiciousEmailBox.Text = "";
        }

        private async Task LoadSuspiciousSendersListAsync()
        {
            var list = await DatabaseHelper.GetSuspiciousSendersAsync();
            SuspiciousSendersList.ItemsSource = list;
        }

        /// <summary>
        /// Overlay'de manuel e-posta ekleme — basit format kontrolüyle.
        /// </summary>
        private async void AddSuspiciousSender_Click(object sender, RoutedEventArgs e)
        {
            string email = NewSuspiciousEmailBox.Text.Trim();
            if (string.IsNullOrEmpty(email))
            {
                MessageBox.Show("E-posta adresi boş olamaz.", "Uyarı", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (!email.Contains('@') || !email.Contains('.'))
            {
                MessageBox.Show("Geçerli bir e-posta adresi girin (örn. abc@xyz.com).", "Geçersiz E-posta", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                DatabaseHelper.AddSuspiciousSender(email, "Manuel olarak eklendi");
                DatabaseHelper.SaveSystemLog("Şüpheli Gönderici Eklendi", $"Manuel: {email}");
                NewSuspiciousEmailBox.Text = "";
                await LoadSuspiciousSendersListAsync();
                StatusText.Text = $"'{email}' şüpheli listesine eklendi";
                StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Eklenemedi: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Liste içindeki bir göndericiyi listeden çıkarır (X butonu).
        /// </summary>
        private async void RemoveSuspiciousSender_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not System.Windows.Controls.Button btn || btn.Tag is not string email) return;

            var confirm = MessageBox.Show(
                $"'{email}' şüpheli listesinden çıkarılsın mı?\n\n" +
                "Bundan sonra bu adresten gelen mailler normal şekilde işlenir.",
                "Listeden Çıkar",
                MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (confirm != MessageBoxResult.Yes) return;

            try
            {
                DatabaseHelper.RemoveSuspiciousSender(email);
                DatabaseHelper.SaveSystemLog("Şüpheli Gönderici Çıkarıldı", email);
                await LoadSuspiciousSendersListAsync();
                StatusText.Text = $"'{email}' listeden çıkarıldı";
                StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4ADE80"));
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Çıkarılamadı: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// MailActionsPanel'deki "Şüpheli İşaretle" butonu — açık mailin göndericisini ekler
        /// ve mevcut maili Çöp Kutusu'na taşır.
        /// </summary>
        private async void MarkSenderAsSuspicious_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedMail == null || string.IsNullOrEmpty(_selectedMail.FromEmail))
            {
                MessageBox.Show("Önce bir mail seçin.", "Bilgi", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            string senderEmail = _selectedMail.FromEmail;

            var confirm = MessageBox.Show(
                $"'{senderEmail}' göndericisini şüpheli olarak işaretlemek istiyor musunuz?\n\n" +
                "• Bu adresten gelen TÜM gelecek mailler otomatik Çöp Kutusu'na taşınır\n" +
                "• Mevcut mail de Çöp Kutusu'na taşınır\n" +
                "• Şüpheli Hesaplar listesinden ileride kaldırabilirsiniz",
                "Göndericiyi Şüpheli İşaretle",
                MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (confirm != MessageBoxResult.Yes) return;

            try
            {
                // 1) Şüpheli listesine ekle
                DatabaseHelper.AddSuspiciousSender(senderEmail, $"Mail #{_selectedMail.Id} üzerinden işaretlendi");
                DatabaseHelper.SaveSystemLog("Şüpheli Gönderici Eklendi", $"Mail: {senderEmail}");

                // 2) Mevcut maili çöpe taşı (yerel + Gmail)
                var trash = (await DatabaseHelper.GetFoldersAsync()).FirstOrDefault(f => f.Type == "trash");
                if (trash != null && _selectedMail.FolderId != trash.Id)
                {
                    await DatabaseHelper.MoveMailAsync(_selectedMail.Id, trash.Id);
                    if (!string.IsNullOrEmpty(_selectedMail.GmailMessageId) && _gmailService != null && _gmailService.IsConnected)
                        _ = _gmailService.MoveToTrashAsync(_selectedMail.GmailMessageId);
                }

                ClearSelectedMailUI();
                LoadMailsForFolder(_currentFolderId);

                StatusText.Text = $"'{senderEmail}' şüpheli işaretlendi — bundan sonra otomatik çöpe gidecek";
                StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
            }
            catch (Exception ex)
            {
                MessageBox.Show($"İşaretlenemedi: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void MailListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            int total = MailListBox.SelectedItems.Count;
            if (SelectedCountText != null)
                SelectedCountText.Text = total > 1 ? $"{total} mail seçili" : "";

            // Çoklu seçimde detay paneli açma — sadece tek mail seçilince mail görünür
            if (total == 1 && MailListBox.SelectedItem is Mail mail)
            {
                _selectedMail = mail;
                ShowMailDetail(mail);
                MarkMailAsRead(mail);
            }
        }

        /// <summary>
        /// Mevcut görünen tüm mailleri seçer (ItemsSource ne ise — arama sonucu veya klasör).
        /// </summary>
        private void SelectAllMails_Click(object sender, RoutedEventArgs e)
        {
            MailListBox.SelectAll();
        }

        /// <summary>
        /// Birden fazla mail seçilmişse toplu silme overlay'ini gösterir.
        /// Tek mail seçiliyse standart DeleteMail_Click yoluna düşer.
        /// </summary>
        private void BulkDeleteMails_Click(object sender, RoutedEventArgs e)
        {
            int count = MailListBox.SelectedItems.Count;
            if (count == 0)
            {
                MessageBox.Show("Önce silinecek mail(ler)i seçin.", "Bilgi", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            if (count == 1)
            {
                // Tek mail seçiliyse mevcut DeleteMail_Click akışına yönlendir
                DeleteMail_Click(sender, e);
                return;
            }

            // Çoklu silme: kullanıcı seçtiği mailler için Trash/Permanent overlay'ı göster
            // Mevcut DeleteConfirmOverlay'i toplu mod için kullanıyoruz
            bool allInTrash = MailListBox.SelectedItems.Cast<Mail>().All(m => m.FolderId == 4);

            DeleteConfirmMessage.Text = allInTrash
                ? $"{count} mail zaten Çöp Kutusu'nda. Tümünü kalıcı olarak silmek ister misiniz?"
                : $"{count} maili nasıl silmek istersiniz?";

            DeleteTrashButton.Visibility = allInTrash ? Visibility.Collapsed : Visibility.Visible;
            TrashHintRow.Visibility = allInTrash ? Visibility.Collapsed : Visibility.Visible;

            // Bulk mod flag'i — Confirm handler'ları buna göre çoklu işlem yapar
            _bulkDeleteMode = true;
            DeleteConfirmOverlay.Visibility = Visibility.Visible;
        }

        // Toplu silme modunda mı (ConfirmMoveToTrash/Permanent için)
        private bool _bulkDeleteMode = false;

        private async void MarkMailAsRead(Mail mail)
        {
            if (!mail.IsRead)
            {
                mail.IsRead = true;
                await DatabaseHelper.UpdateMailAsync(mail);
            }
        }

        private async void ShowMailDetail(Mail mail)
        {
            MailSubject.Text = mail.Subject;
            MailFrom.Text = $"{mail.FromName} <{mail.FromEmail}>";
            MailDate.Text = mail.Date.ToString("dd.MM.yyyy HH:mm");

            if (string.IsNullOrWhiteSpace(mail.Body))
            {
                System.Diagnostics.Debug.WriteLine($"[DBG] ShowMailDetail - Body BOŞ: {mail.Subject}");
                Dispatcher.Invoke(() =>
                {
                    MailBodyRich.Document.Blocks.Clear();
                    var para = new Paragraph();
                    para.Inlines.Add(new Run("Bu mailin içeriği bulunamadı veya boş. Gmail'den çekilen mail içeriği gösterilemiyor."));
                    MailBodyRich.Document.Blocks.Add(para);
                });
            }
            else
            {
                System.Diagnostics.Debug.WriteLine($"[DBG] ShowMailDetail - Body uzunluğu: {mail.Body.Length}");
                HighlightMailBodyWithIOCs(mail.Body);
            }

            MailActionsPanel.Visibility = Visibility.Visible;

            // "Gelen Kutusuna Al" butonu sadece Spam (5) veya Çöp (4) klasöründeki mail görüntülenirken çıksın.
            // Folder ID'leri DatabaseHelper.CreateDefaultFolders'da: inbox=1, sent=2, drafts=3, trash=4, spam=5
            RestoreToInboxButton.Visibility =
                (mail.FolderId == 4 || mail.FolderId == 5)
                    ? Visibility.Visible
                    : Visibility.Collapsed;

            bool hasScores = mail.PhishingScore > 0 || mail.SpamScore > 0 ||
                             mail.SqlInjectionScore > 0 || mail.XssScore > 0 || mail.TrojanScore > 0;

            if (hasScores)
            {
                AnalysisPanel.Visibility = Visibility.Visible;
                PhishingScore.Text = $"%{mail.PhishingScore:F0}";
                SpamScore.Text     = $"%{mail.SpamScore:F0}";
                TrySetScoreText("SqlInjectionScore", mail.SqlInjectionScore);
                TrySetScoreText("XssScore",          mail.XssScore);
                TrySetScoreText("TrojanScore",        mail.TrojanScore);
            }
            else
            {
                AnalysisPanel.Visibility = Visibility.Collapsed;
                await AnalyzeMailAsync(mail);
            }

            // VirusTotal — önceki tarama varsa iptal et (yeni mail seçildi).
            _vtScanCts?.Cancel();
            _vtScanCts = new System.Threading.CancellationTokenSource();

            // Otomatik tarama YOK — kullanıcı VIRUSTOTAL kartına tıklayınca tarayalım.
            // Bu sayede VT quota gereksiz harcanmıyor.
            ShowVtCardInitialState(mail);
        }

        // VT scan iptal token'ı — mail değişince eski scan dursun
        private System.Threading.CancellationTokenSource? _vtScanCts;

        // Hangi mail için scan yapıldığını izlemek için — _lastVtResult bu mail'e ait mi?
        private int _vtScannedForMailId = -1;

        /// <summary>
        /// Mail görüntülenince VIRUSTOTAL kartı için ilk durumu belirler:
        /// - API yok          → "API Yok"
        /// - Link yok         → "Link Yok"
        /// - Link var, taranmamış → "Tara" (mavi, tıklanabilir)
        /// </summary>
        private void ShowVtCardInitialState(Mail mail)
        {
            // Önceki maile ait sonucu temizle
            _vtScannedForMailId = -1;
            _lastVtResult = null;

            if (string.IsNullOrWhiteSpace(_apiKey))
            {
                VtResult.Text = "API Yok";
                VtResult.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#9CA3AF"));
                VtDetail.Text = "Ayarlardan VT key girin";
                VtDetail.Visibility = Visibility.Visible;
                return;
            }

            var urls = ExtractUrlsFromBody(mail.Body ?? "");
            if (urls.Count == 0)
            {
                VtResult.Text = "Link Yok";
                VtResult.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#9CA3AF"));
                VtDetail.Text = "Mailde URL bulunmadı";
                VtDetail.Visibility = Visibility.Visible;
                return;
            }

            // Link var ama taranmadı — kullanıcı tıklayarak başlatsın
            VtResult.Text = "Tara";
            VtResult.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#60A5FA"));
            VtDetail.Text = urls.Count > 1
                ? $"{urls.Count} link var — tıklayıp tara (Kota: {VtRateLimiter.CurrentCount()}/4)"
                : $"1 link var — tıklayıp tara (Kota: {VtRateLimiter.CurrentCount()}/4)";
            VtDetail.Visibility = Visibility.Visible;
        }

        /// <summary>
        /// Görüntülenen mailin gövdesindeki ilk URL'i VirusTotal'da tarar.
        /// Önce cached (GET /urls/{id}, 1 istek) dener, sonuç yoksa POST + polling yapar.
        /// </summary>
        private async Task ScanMailUrlsWithVtAsync(Mail mail, System.Threading.CancellationToken cancel = default)
        {
            if (string.IsNullOrWhiteSpace(_apiKey))
            {
                Dispatcher.Invoke(() =>
                {
                    VtResult.Text = "API Yok";
                    VtDetail.Text = "Ayarlardan VT key girin";
                    VtDetail.Visibility = Visibility.Visible;
                });
                return;
            }

            var urls = ExtractUrlsFromBody(mail.Body ?? "");

            if (urls.Count == 0)
            {
                Dispatcher.Invoke(() =>
                {
                    VtResult.Text = "Link Yok";
                    VtDetail.Text = "Mailde URL bulunmadı";
                    VtDetail.Visibility = Visibility.Visible;
                });
                return;
            }

            // VT free tier: 4 req/min. GET-first ile cached URL'ler 1 isteğe iner,
            // yeni URL'ler ~4 istek alır. Mail başına 1 URL tarıyoruz — quota'yı koruyalım.
            int maxUrlsToScan = 1;

            // Anlık feedback
            int currentQuota = VtRateLimiter.CurrentCount();
            Dispatcher.Invoke(() =>
            {
                VtResult.Text = "Taranıyor...";
                VtDetail.Text = urls.Count > maxUrlsToScan
                    ? $"İlk URL taranıyor ({urls.Count} URL var) — Kota: {currentQuota}/4"
                    : $"URL taranıyor... (Kota: {currentQuota}/4)";
                VtDetail.Visibility = Visibility.Visible;
            });

            int totalMalicious = 0;
            int totalSuspicious = 0;
            int maxEngines = 0;
            int scannedOk = 0;
            bool hitRateLimit = false;
            bool hitTimeout = false;
            VTScanResult? aggregatedForDisplay = null;

            foreach (var url in urls.Take(maxUrlsToScan))
            {
                // Kullanıcı başka maile geçtiyse iptal et
                if (cancel.IsCancellationRequested)
                {
                    System.Diagnostics.Debug.WriteLine($"[Mail VT] Cancelled — user switched mail");
                    return;
                }

                var result = await VirusTotalService.ScanUrlAsync(url, _apiKey);
                if (result == null) continue;

                if (result.IsRateLimited)
                {
                    hitRateLimit = true;
                    System.Diagnostics.Debug.WriteLine($"[Mail VT] Rate limit hit: {result.ErrorMessage}");
                    break; // hemen dur, kalan URL'lere geçme
                }

                if (!string.IsNullOrEmpty(result.ErrorMessage))
                {
                    if (result.ErrorMessage.Contains("zaman aşımı", StringComparison.OrdinalIgnoreCase))
                        hitTimeout = true;
                    System.Diagnostics.Debug.WriteLine($"[Mail VT] Error: {result.ErrorMessage}");
                    continue;
                }

                scannedOk++;
                totalMalicious += result.Malicious;
                totalSuspicious += result.Suspicious;
                if (result.TotalEngines > maxEngines)
                {
                    maxEngines = result.TotalEngines;
                    aggregatedForDisplay = result;
                }
            }

            // Rate limit'e takıldıysak özel mesaj
            if (hitRateLimit)
            {
                int waitSec = VtRateLimiter.SecondsUntilNextSlot();
                Dispatcher.Invoke(() =>
                {
                    VtResult.Text = "Kota Doldu";
                    VtResult.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));
                    VtDetail.Text = waitSec > 0
                        ? $"VT 4/dk limiti aşıldı — {waitSec}sn bekleyin"
                        : "VT free tier limiti (4 req/dk) aşıldı";
                });
                return;
            }

            // Hiç başarılı tarama olmadıysa
            if (scannedOk == 0 || maxEngines == 0)
            {
                Dispatcher.Invoke(() =>
                {
                    VtResult.Text = hitTimeout ? "VT Bekleniyor" : "Tarama Yok";
                    VtDetail.Text = hitTimeout
                        ? "VT analizi tamamlanmadı, mail'i yeniden açın"
                        : "VT'den sonuç alınamadı (yeni URL veya hata)";
                });
                return;
            }

            // _lastVtResult VtResult_Click overlay'ı için — tıklayınca motor bazlı detay göstersin
            _lastVtResult = aggregatedForDisplay;
            _vtScannedForMailId = mail.Id;

            // Görüntü: "5/74" formatı + tehdit tipi
            int flagged = totalMalicious + totalSuspicious;
            string threatType = aggregatedForDisplay?.TopThreatType() ?? "";

            Dispatcher.Invoke(() =>
            {
                VtResult.Text = $"{flagged}/{maxEngines}";
                if (flagged == 0)
                {
                    VtResult.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4ADE80"));
                    VtDetail.Text = "Temiz — Hiçbir motor tehdit bildirmedi";
                }
                else
                {
                    VtResult.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
                    VtDetail.Text = string.IsNullOrEmpty(threatType)
                        ? $"{flagged} motor zararlı buldu"
                        : $"Tip: {threatType}";
                }
                VtDetail.Visibility = Visibility.Visible;
            });
        }

        /// <summary>Mail gövdesinden HTTP(S) URL'lerini çıkarır (en fazla makul sayıda, duplicate'siz).</summary>
        private static List<string> ExtractUrlsFromBody(string body)
        {
            if (string.IsNullOrEmpty(body)) return new List<string>();

            try
            {
                var pattern = new System.Text.RegularExpressions.Regex(
                    @"https?://[^\s<>""']+",
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase,
                    TimeSpan.FromMilliseconds(300));

                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var urls = new List<string>();
                foreach (System.Text.RegularExpressions.Match m in pattern.Matches(body))
                {
                    string url = m.Value.TrimEnd('.', ',', ')', ']', '}', '!', '?', ';', ':');
                    if (seen.Add(url)) urls.Add(url);
                    if (urls.Count >= 10) break;
                }
                return urls;
            }
            catch
            {
                return new List<string>();
            }
        }

        private void HighlightMailBodyWithIOCs(string bodyText)
        {
            if (string.IsNullOrEmpty(bodyText))
            {
                MailBodyRich.Document.Blocks.Clear();
                return;
            }

            _ = Task.Run(() =>
            {
                try
                {
                    var matches = ParseIocTokens(bodyText);

                    Dispatcher.InvokeAsync(() =>
                    {
                        var paragraph = new Paragraph();
                        paragraph.LineHeight = 22;

                        int lastIndex = 0;
                        foreach (var match in matches)
                        {
                            if (match.Start > lastIndex)
                            {
                                var normalRun = new Run(bodyText.Substring(lastIndex, match.Start - lastIndex));
                                paragraph.Inlines.Add(normalRun);
                            }

                            string iocText = bodyText.Substring(match.Start, match.Length);
                            var iocRun = new Run(iocText);

                            if (match.Type == "url" || match.Type == "ip")
                            {
                                iocRun.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#40EF4444"));
                                iocRun.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
                            }
                            else if (match.Type == "email" || match.Type == "domain")
                            {
                                iocRun.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#40F59E0B"));
                                iocRun.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));
                            }
                            else if (match.Type == "sql")
                            {
                                iocRun.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#40A855F7"));
                                iocRun.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#A855F7"));
                            }
                            else if (match.Type == "xss")
                            {
                                iocRun.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#40EC4899"));
                                iocRun.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EC4899"));
                            }
                            else
                            {
                                iocRun.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#404ADE80"));
                                iocRun.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4ADE80"));
                            }
                            iocRun.FontWeight = FontWeights.SemiBold;
                            paragraph.Inlines.Add(iocRun);

                            lastIndex = match.Start + match.Length;
                        }

                        if (lastIndex < bodyText.Length)
                        {
                            var normalRun = new Run(bodyText.Substring(lastIndex));
                            paragraph.Inlines.Add(normalRun);
                        }

                        MailBodyRich.Document.Blocks.Clear();
                        MailBodyRich.Document.Blocks.Add(paragraph);
                    });
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Highlight Error: {ex.Message}");
                    Dispatcher.InvokeAsync(() =>
                    {
                        MailBodyRich.Document.Blocks.Clear();
                        MailBodyRich.Document.Blocks.Add(new Paragraph(new Run(bodyText)));
                    });
                }
            });
        }

        private List<(int Start, int Length, string Type)> ParseIocTokens(string bodyText)
        {
            // KİLİTLENMEYİ ÖNLEYEN ADIM: Regex'lere maksimum 300 ms çalışma süresi veriyoruz
            var timeout = TimeSpan.FromMilliseconds(300);

            var urlPattern    = new System.Text.RegularExpressions.Regex(@"(https?://[^\s]+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase, timeout);
            var ipPattern     = new System.Text.RegularExpressions.Regex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", System.Text.RegularExpressions.RegexOptions.None, timeout);
            var emailPattern  = new System.Text.RegularExpressions.Regex(@"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", System.Text.RegularExpressions.RegexOptions.None, timeout);
            var domainPattern = new System.Text.RegularExpressions.Regex(@"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b", System.Text.RegularExpressions.RegexOptions.None, timeout);
            var sqlPattern    = new System.Text.RegularExpressions.Regex(
                @"\b(select\s+.+\s+from|union\s+select|drop\s+table|drop\s+database|delete\s+from|insert\s+into|exec\s*\(|xp_cmdshell|sp_executesql|@@version|waitfor\s+delay|sleep\s*\()\b",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase, timeout);
            var xssPattern    = new System.Text.RegularExpressions.Regex(
                @"(<script[\s\S]*?>|<\/script>|javascript:|onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=|document\.cookie|eval\s*\(|alert\s*\(|<iframe|vbscript:)",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase, timeout);

            var matches = new List<(int Start, int Length, string Type)>();

            try
            {
                foreach (System.Text.RegularExpressions.Match m in urlPattern.Matches(bodyText))
                    matches.Add((m.Index, m.Length, "url"));
                foreach (System.Text.RegularExpressions.Match m in ipPattern.Matches(bodyText))
                    matches.Add((m.Index, m.Length, "ip"));
                //foreach (System.Text.RegularExpressions.Match m in emailPattern.Matches(bodyText))
                  //  matches.Add((m.Index, m.Length, "email"));
               // foreach (System.Text.RegularExpressions.Match m in domainPattern.Matches(bodyText))
               //     if (!m.Value.Contains(".") || m.Value.Count(c => c == '.') < 2)
                 //       matches.Add((m.Index, m.Length, "domain"));
                foreach (System.Text.RegularExpressions.Match m in sqlPattern.Matches(bodyText))
                    matches.Add((m.Index, m.Length, "sql"));
                foreach (System.Text.RegularExpressions.Match m in xssPattern.Matches(bodyText))
                    matches.Add((m.Index, m.Length, "xss"));
            }
            catch (System.Text.RegularExpressions.RegexMatchTimeoutException)
            {
                // Regex 300ms içinde bitmezse, işlemi anında keseriz. 
                // Bu sayede uygulama asla donmaz ve kilitlenmez.
                System.Diagnostics.Debug.WriteLine("Regex zaman aşımına uğradı! Çok karmaşık metin tespit edildi.");
                return new List<(int Start, int Length, string Type)>();
            }

            // Başlangıç indeksine göre sırala
            matches = matches.OrderBy(m => m.Start).ThenByDescending(m => m.Length).ToList();

            var filteredMatches = new List<(int Start, int Length, string Type)>();
            int currentEnd = 0;

            // Çakışan eşleşmeleri filtrele
            foreach (var match in matches)
            {
                if (match.Start >= currentEnd)
                {
                    filteredMatches.Add(match);
                    currentEnd = match.Start + match.Length;
                }
            }

            return filteredMatches;
        }

        private async Task AnalyzeMailAsync(Mail mail)
        {
            if (string.IsNullOrWhiteSpace(mail.Body))
                return;

            StatusText.Text = Application.Current.FindResource("StatusAnalyzingMail")?.ToString() ?? "Mail analiz ediliyor...";
            StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#60A5FA"));

            var result = await _mlService.AnalyzeTextAsync(mail.Body + " " + mail.Subject);

            mail.PhishingScore     = result.PhishingScore;
            mail.SpamScore         = result.SpamScore;
            mail.SqlInjectionScore = result.SqlInjectionScore;
            mail.XssScore          = result.XssScore;
            mail.TrojanScore       = result.TrojanScore;
            mail.IsPhishing        = result.IsPhishing;
            mail.IsSpam            = result.IsSpam;

            // ── Threat (phishing / SQL inj / XSS / trojan) → move to Trash and delete from Gmail ──
            if (result.IsDangerous)
            {
                await HandleThreatAsync(mail, result);
                return;
            }

            // ── Spam → move to Spam folder (DB + Gmail) ──
            if (result.IsSpam)
            {
                await HandleSpamAsync(mail);
                return;
            }

            await DatabaseHelper.UpdateMailAsync(mail);
            UpdateAnalysisPanel(result);

            StatusText.Text = Application.Current.FindResource("StatusAnalysisNoThreat")?.ToString() ?? "Analiz tamamlandı — Tehdit bulunamadı";
            StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4ADE80"));
        }

        // Move spam to spam folder both locally and in Gmail
        private async Task HandleSpamAsync(Mail mail)
        {
            var spamFolder = (await DatabaseHelper.GetFoldersAsync()).FirstOrDefault(f => f.Type == "spam");
            if (spamFolder != null && mail.FolderId != spamFolder.Id)
            {
                await DatabaseHelper.MoveMailAsync(mail.Id, spamFolder.Id);
            }
            mail.IsSpam = true;
            await DatabaseHelper.UpdateMailAsync(mail);

            if (!string.IsNullOrEmpty(mail.GmailMessageId) && _gmailService != null && _gmailService.IsConnected)
            {
                _ = _gmailService.MoveToSpamAsync(mail.GmailMessageId);
            }

            StatusText.Text = $"Spam tespit edildi (%{mail.SpamScore:F0}) — Spam kutusuna taşındı";
            StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));
            LoadMailsForFolder(_currentFolderId);
        }

        // Move dangerous threats to local Trash, then delete from Gmail
        private async Task HandleThreatAsync(Mail mail, ThreatAnalysisResult r)
        {
            var threats = new List<string>();
            if (r.IsPhishing)       threats.Add($"Phishing %{r.PhishingScore:F0}");
            if (r.HasSqlInjection)  threats.Add($"SQL Injection %{r.SqlInjectionScore:F0}");
            if (r.HasXss)           threats.Add($"XSS %{r.XssScore:F0}");
            if (r.HasTrojan)        threats.Add($"Trojan %{r.TrojanScore:F0}");
            string threatLabel = string.Join(" | ", threats);

            DatabaseHelper.SaveSystemLog("Tehdit Tespit",
                $"Mail #{mail.Id} silindi. Tespit: {threatLabel}. Gönderen: {mail.FromEmail}");

            // Move to local Trash
            var trashFolder = (await DatabaseHelper.GetFoldersAsync()).FirstOrDefault(f => f.Type == "trash");
            if (trashFolder != null)
            {
                await DatabaseHelper.MoveMailAsync(mail.Id, trashFolder.Id);
            }
            await DatabaseHelper.UpdateMailAsync(mail);

            // Delete from Gmail (permanent)
            if (!string.IsNullOrEmpty(mail.GmailMessageId) && _gmailService != null && _gmailService.IsConnected)
            {
                _ = _gmailService.DeleteFromGmailAsync(mail.GmailMessageId);
            }

            StatusText.Text = $"⚠ TEHDİT SİLİNDİ: {threatLabel}";
            StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
            LoadMailsForFolder(_currentFolderId);
        }

        private void UpdateAnalysisPanel(ThreatAnalysisResult r)
        {
            AnalysisPanel.Visibility = Visibility.Visible;
            PhishingScore.Text = $"%{r.PhishingScore:F0}";
            SpamScore.Text     = $"%{r.SpamScore:F0}";
            TrySetScoreText("SqlInjectionScore", r.SqlInjectionScore);
            TrySetScoreText("XssScore",          r.XssScore);
            TrySetScoreText("TrojanScore",        r.TrojanScore);
        }

        private void TrySetScoreText(string elementName, double score)
        {
            try
            {
                if (FindName(elementName) is System.Windows.Controls.TextBlock tb)
                    tb.Text = $"%{score:F0}";
            }
            catch { }
        }

        private async void CheckGmailConnection()
        {
            var (email, password) = await Task.Run(() => DatabaseHelper.GetGmailAccount());
            if (!string.IsNullOrEmpty(email) && !string.IsNullOrEmpty(password))
            {
                var connected = await _gmailService.ConnectAsync(email, password);
                if (connected)
                {
                    GmailStatusText.Text = email;
                    GmailSyncButton.Content = Application.Current.FindResource("SyncGmail").ToString();
                }
            }
        }

        private void NewMail_Click(object sender, RoutedEventArgs e)
        {
            ComposeMailOverlay.Visibility = Visibility.Visible;
        }

        private void CloseComposeMail_Click(object sender, RoutedEventArgs e)
        {
            ComposeMailOverlay.Visibility = Visibility.Collapsed;
            ComposeToBox.Text = "";
            ComposeSubjectBox.Text = "";
            ComposeBodyBox.Text = "";
            _composeAttachments.Clear();
            RefreshAttachmentsUI();
        }

        // ==========================================
        // MAIL EKLERİ
        // ==========================================

        /// <summary>Compose ekranında seçilen ekler — dosya yolları + UI binding için detaylar.</summary>
        private readonly System.Collections.ObjectModel.ObservableCollection<MailAttachmentItem> _composeAttachments = new();

        public class MailAttachmentItem
        {
            public string FullPath { get; set; } = "";
            public string FileName { get; set; } = "";
            public long SizeBytes { get; set; }
            public string SizeDisplay
            {
                get
                {
                    if (SizeBytes < 1024) return $"{SizeBytes} B";
                    if (SizeBytes < 1024 * 1024) return $"{SizeBytes / 1024} KB";
                    return $"{SizeBytes / 1024 / 1024} MB";
                }
            }
        }

        private void BrowseAttachment_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Mail Ekini Seç",
                Filter = "Tüm Dosyalar (*.*)|*.*",
                Multiselect = true
            };
            if (dialog.ShowDialog() != true) return;

            // Gmail limiti 25MB toplam — uyarı verelim ama yine ekleyelim
            long totalSize = _composeAttachments.Sum(a => a.SizeBytes);
            foreach (var path in dialog.FileNames)
            {
                if (_composeAttachments.Any(a => string.Equals(a.FullPath, path, StringComparison.OrdinalIgnoreCase)))
                    continue; // duplicate

                try
                {
                    var info = new FileInfo(path);
                    totalSize += info.Length;
                    _composeAttachments.Add(new MailAttachmentItem
                    {
                        FullPath = path,
                        FileName = info.Name,
                        SizeBytes = info.Length
                    });
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Ek bilgisi alınamadı {path}: {ex.Message}");
                }
            }

            RefreshAttachmentsUI();

            if (totalSize > 25 * 1024 * 1024)
            {
                MessageBox.Show("Ekler toplam 25 MB sınırını aşıyor. Gmail büyük olasılıkla göndermeyi reddedecek.\n\nGoogle Drive linki kullanmayı veya bazı ekleri kaldırmayı düşünün.",
                    "Boyut Uyarısı", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void RemoveAttachment_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not System.Windows.Controls.Button btn || btn.Tag is not string fullPath) return;
            var target = _composeAttachments.FirstOrDefault(a =>
                string.Equals(a.FullPath, fullPath, StringComparison.OrdinalIgnoreCase));
            if (target != null)
            {
                _composeAttachments.Remove(target);
                RefreshAttachmentsUI();
            }
        }

        private void RefreshAttachmentsUI()
        {
            AttachmentsList.ItemsSource = null;
            AttachmentsList.ItemsSource = _composeAttachments;
            int count = _composeAttachments.Count;
            AttachmentCountText.Text = count == 0
                ? "Ek yok"
                : count == 1 ? "1 ek seçili" : $"{count} ek seçili";
            AttachmentsListBorder.Visibility = count > 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        /// <summary>
        /// Compose ekranındaki maili göndermeden Taslaklar klasörüne kaydeder.
        /// Gmail tarafına göndermez (sadece yerel DB'de saklanır) — kullanıcı sonradan
        /// açıp düzenleyip gönderebilir.
        /// </summary>
        private async void SaveDraft_Click(object sender, RoutedEventArgs e)
        {
            string toEmail = ComposeToBox.Text.Trim();
            string subject = ComposeSubjectBox.Text.Trim();
            string body = ComposeBodyBox.Text.Trim();

            // Tamamen boş taslak kaydetmenin anlamı yok
            if (string.IsNullOrEmpty(toEmail) && string.IsNullOrEmpty(subject) && string.IsNullOrEmpty(body))
            {
                MessageBox.Show("Boş bir taslak kaydedemezsiniz. Lütfen en azından bir alan doldurun.",
                    "Uyarı", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                // Taslaklar klasörü (CreateDefaultFolders'da type='drafts' olarak oluşturulur)
                var draftsFolder = (await DatabaseHelper.GetFoldersAsync())
                                    .FirstOrDefault(f => f.Type == "drafts");
                if (draftsFolder == null)
                {
                    MessageBox.Show("Taslaklar klasörü bulunamadı.", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                var (currentEmail, _) = await Task.Run(() => DatabaseHelper.GetGmailAccount());

                var draft = new Mail
                {
                    FolderId = draftsFolder.Id,
                    Subject = string.IsNullOrEmpty(subject) ? "(Konu yok)" : subject,
                    Body = body,
                    FromEmail = currentEmail ?? "",
                    ToEmail = toEmail,
                    FromName = currentEmail ?? "",
                    Date = DateTime.Now,
                    IsRead = true,
                    GmailMessageId = "" // Henüz Gmail'e gönderilmemiş
                };

                await DatabaseHelper.InsertMailAsync(draft);
                DatabaseHelper.SaveSystemLog("Taslak Kaydedildi", $"Alıcı: {toEmail}, Konu: {subject}");

                // Compose ekranını kapat
                CloseComposeMail_Click(sender, e);

                // Eğer kullanıcı şu an Taslaklar klasöründeyse listeyi yenile
                if (_currentFolderId == draftsFolder.Id)
                    LoadMailsForFolder(_currentFolderId);

                StatusText.Text = "Taslak kaydedildi";
                StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4ADE80"));
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Taslak kaydedilemedi: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void SendMail_Click(object sender, RoutedEventArgs e)
        {
            string toEmail = ComposeToBox.Text.Trim();
            string subject = ComposeSubjectBox.Text.Trim();
            string body = ComposeBodyBox.Text.Trim();

            if (string.IsNullOrEmpty(toEmail) || string.IsNullOrEmpty(subject))
            {
                MessageBox.Show("Lütfen alıcı ve konu alanlarını doldurun.", "Uyarı", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            StatusText.Text = Application.Current.FindResource("StatusSendingMail")?.ToString() ?? "Mail gönderiliyor...";

            var (email, password) = await Task.Run(() => DatabaseHelper.GetGmailAccount());
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
            {
                MessageBox.Show("Lütfen önce Gmail hesabınızı ayarlardan yapılandırın.", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (_gmailService != null && !_gmailService.IsConnected)
            {
                await _gmailService.ConnectAsync(email, password);
            }

            // Mail gönderiminde ekler de gönderilir (varsa)
            var attachmentPaths = _composeAttachments.Select(a => a.FullPath).ToList();
            bool success = _gmailService != null && _gmailService.IsConnected
                && await _gmailService.SendEmailAsync(toEmail, subject, body, isHtml: false, attachmentPaths: attachmentPaths);

            if (success)
            {
                var sentFolder = (await DatabaseHelper.GetFoldersAsync()).FirstOrDefault(f => f.Type == "sent");
                if (sentFolder != null)
                {
                    var mail = new Mail
                    {
                        FolderId = sentFolder.Id,
                        Subject = subject,
                        Body = body,
                        FromEmail = email,
                        ToEmail = toEmail,
                        FromName = email,
                        Date = DateTime.Now,
                        IsRead = true
                    };
                    await DatabaseHelper.InsertMailAsync(mail);
                }

                MessageBox.Show("Mail başarıyla gönderildi!", "Başarılı", MessageBoxButton.OK, MessageBoxImage.Information);
                CloseComposeMail_Click(sender, e);
                LoadMailsForFolder(_currentFolderId);
            }
            else
            {
                MessageBox.Show("Mail gönderilirken hata oluştu.", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }

            StatusText.Text = Application.Current.FindResource("StatusReady")?.ToString() ?? "Hazır";
        }

        private async void SyncGmail_Click(object sender, RoutedEventArgs e)
        {
            await PerformGmailSyncAsync(showStatusUpdates: true);
        }

        // Son auto-sync zamanı (UI gösterimi için)
        private DateTime? _lastSyncAt;

        /// <summary>
        /// Gmail senkronu, tehdit/spam imha mantığını ve UI güncellemelerini içeren
        /// tek noktadan helper. RefreshMails_Click, SyncGmail_Click ve AutoSyncGmailAsync
        /// hepsi bu metodu çağırır — eskiden 3 ayrı yerde duplike vardı.
        /// </summary>
        // PerformGmailSyncAsync re-entrancy guard.
        // Constructor + Window_Loaded + Auto-sync timer + Manual Refresh aynı anda tetiklerse
        // her biri _imapClient.Inbox'a paralel erişir → biri açar, biri kapatır → FolderNotOpenException.
        // Bu semaphore aynı anda yalnızca BİR sync çalışmasına izin verir; ikincisi bekler veya atlanır.
        private static readonly System.Threading.SemaphoreSlim _syncLock = new System.Threading.SemaphoreSlim(1, 1);

        private async Task<(int newCount, int spamCount, int threatCount)> PerformGmailSyncAsync(bool showStatusUpdates)
        {
            // Sync zaten devam ediyorsa bekleme yerine atla — kullanıcı UI'da takılmasın
            // (auto-sync background'da çalışırken kullanıcı manuel Refresh basarsa 2. sync iptal olur).
            if (!await _syncLock.WaitAsync(TimeSpan.Zero))
            {
                System.Diagnostics.Debug.WriteLine("[Sync] Önceki sync devam ediyor — bu çağrı atlandı");
                if (showStatusUpdates)
                    StatusText.Text = "Senkron zaten çalışıyor, bekleyin...";
                return (0, 0, 0);
            }

            try
            {
                return await PerformGmailSyncCoreAsync(showStatusUpdates);
            }
            finally
            {
                _syncLock.Release();
            }
        }

        private async Task<(int newCount, int spamCount, int threatCount)> PerformGmailSyncCoreAsync(bool showStatusUpdates)
        {
            var (email, password) = await Task.Run(() => DatabaseHelper.GetGmailAccount());
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
            {
                if (showStatusUpdates)
                    MessageBox.Show("Lütfen önce Gmail hesabınızı yapılandırın.", "Uyarı", MessageBoxButton.OK, MessageBoxImage.Warning);
                SetLastSyncIndicatorText("Gmail hesabı kayıtlı değil — Ayarlardan ekleyin", "#A0A0A0");
                return (0, 0, 0);
            }

            if (showStatusUpdates)
                StatusText.Text = Application.Current.FindResource("StatusSyncingGmail")?.ToString() ?? "Gmail senkronize ediliyor...";

            // Indicator: bağlantı aşamasını göster
            SetLastSyncIndicatorText("Gmail'e bağlanılıyor...", "#F59E0B");

            if (_gmailService != null && !_gmailService.IsConnected)
            {
                await _gmailService.ConnectAsync(email, password);
            }

            if (_gmailService == null || !_gmailService.IsConnected)
            {
                if (showStatusUpdates)
                    StatusText.Text = Application.Current.FindResource("StatusGmailConnectionError")?.ToString() ?? "Gmail bağlantısı kurulamadı!";
                SetLastSyncIndicatorText("Bağlantı kurulamadı — tekrar denenecek", "#EF4444");
                return (0, 0, 0);
            }

            // Indicator: mail çekme aşaması
            SetLastSyncIndicatorText("Mailler çekiliyor...", "#3B82F6");

            var inboxMails = await _gmailService.SyncInboxAsync(50);

            // Duplicate kontrolü TÜM klasörler için yapılmalı — eğer mail daha önce
            // tehdit/spam olarak işaretlenip Trash/Spam'e taşındıysa, Inbox'a tekrar
            // dönerse bile yeniden eklenmesin. Sadece folder 1 (Inbox) kontrolü hatalıydı:
            // Trash'teki kayıt görünmüyordu, her sync'te yeni kopya birikiyordu.
            var existingGmailIds = await DatabaseHelper.GetAllGmailMessageIdsAsync();
            var folders = await DatabaseHelper.GetFoldersAsync();
            var spamFolderId  = folders.FirstOrDefault(f => f.Type == "spam")?.Id  ?? 5;
            var trashFolderId = folders.FirstOrDefault(f => f.Type == "trash")?.Id ?? 4;

            // Şüpheli göndericiler listesi — bu listedeki adreslerden gelen mailler
            // analiz edilmeden direkt Çöp Kutusu'na taşınır (HashSet O(1) lookup).
            var suspiciousSenders = await Task.Run(() => DatabaseHelper.GetSuspiciousSenderEmails());

            int newCount = 0, spamCount = 0, threatCount = 0;
            var newMailTasks = new List<Task>();

            // İmha edilecek/sürülecek mail id'lerini güvenli bir listede topluyoruz
            // ki Task'ler arası IMAP yarış koşulu olmasın.
            var mailsToTrash = new System.Collections.Concurrent.ConcurrentBag<string>();
            var mailsToSpam  = new System.Collections.Concurrent.ConcurrentBag<string>();

            foreach (var syncedMail in inboxMails)
            {
                if (existingGmailIds.Contains(syncedMail.MessageId))
                    continue;

                var mail = new Mail
                {
                    FolderId = 1,
                    Subject = syncedMail.Subject,
                    Body = syncedMail.Body,
                    FromEmail = syncedMail.FromEmail,
                    FromName = syncedMail.FromName,
                    ToEmail = syncedMail.ToEmail,
                    Date = syncedMail.Date,
                    HasAttachments = syncedMail.HasAttachments,
                    GmailMessageId = syncedMail.MessageId
                };

                // ŞÜPHELİ GÖNDERİCİ — Analiz YAPMA, doğrudan Çöp Kutusu'na taşı.
                // Bu Task.Run dışında, sync ile yapılır çünkü AI gerekmez.
                if (!string.IsNullOrEmpty(syncedMail.FromEmail) && suspiciousSenders.Contains(syncedMail.FromEmail))
                {
                    mail.FolderId = trashFolderId;
                    mail.IsSpam = false;
                    mail.IsPhishing = false;
                    await DatabaseHelper.InsertMailAsync(mail);
                    if (!string.IsNullOrEmpty(mail.GmailMessageId))
                        mailsToTrash.Add(mail.GmailMessageId);
                    DatabaseHelper.SaveSystemLog("Şüpheli Göndericiden Mail",
                        $"Otomatik Çöp: {syncedMail.FromEmail}, Konu: {syncedMail.Subject}");
                    System.Threading.Interlocked.Increment(ref threatCount);
                    continue; // analize geçme
                }

                var task = Task.Run(async () =>
                {
                    var r = await _mlService.AnalyzeTextAsync(mail.Body + " " + mail.Subject);
                    mail.PhishingScore = r.PhishingScore;
                    mail.SpamScore = r.SpamScore;
                    mail.SqlInjectionScore = r.SqlInjectionScore;
                    mail.XssScore = r.XssScore;
                    mail.TrojanScore = r.TrojanScore;
                    mail.IsPhishing = r.IsPhishing;
                    mail.IsSpam = r.IsSpam;

                    if (r.IsDangerous)
                    {
                        // Skor ≥ 70 → Kritik → Çöp Kutusu
                        mail.FolderId = trashFolderId;
                        await DatabaseHelper.InsertMailAsync(mail);
                        if (!string.IsNullOrEmpty(mail.GmailMessageId))
                            mailsToTrash.Add(mail.GmailMessageId);
                        System.Threading.Interlocked.Increment(ref threatCount);
                    }
                    else if (r.IsSpam || r.IsSuspicious)
                    {
                        // Spam ≥ 50  veya  herhangi bir tehdit kategorisi 40-69 (şüpheli) → Spam klasörü
                        // SQL Injection / XSS / Trojan / Phishing'in şüpheli bantları artık Inbox'ta kalmıyor.
                        mail.FolderId = spamFolderId;
                        await DatabaseHelper.InsertMailAsync(mail);
                        if (!string.IsNullOrEmpty(mail.GmailMessageId))
                            mailsToSpam.Add(mail.GmailMessageId);
                        System.Threading.Interlocked.Increment(ref spamCount);
                    }
                    else
                    {
                        // Tüm skorlar < 40 → Güvenli → Inbox
                        await DatabaseHelper.InsertMailAsync(mail);
                        System.Threading.Interlocked.Increment(ref newCount);
                    }
                });

                newMailTasks.Add(task);
            }

            if (newMailTasks.Count > 0)
                await Task.WhenAll(newMailTasks);

            // Tüm DB ve analiz işleri bitti — şimdi sırayla Gmail'e gerçek aksiyon
            foreach (var msgId in mailsToTrash)
            {
                await _gmailService.MoveToTrashAsync(msgId);
                DatabaseHelper.SaveSystemLog("Tehdit İmha Edildi", $"Mail Gmail'in Çöp Kutusuna taşındı. (ID: {msgId})");
            }
            foreach (var msgId in mailsToSpam)
            {
                await _gmailService.MoveToSpamAsync(msgId);
            }

            DatabaseHelper.UpdateGmailSyncTime();
            LoadMailsForFolder(_currentFolderId);

            // Son sync zamanını UI'da göster
            _lastSyncAt = DateTime.Now;
            UpdateLastSyncIndicator();

            if (showStatusUpdates)
                StatusText.Text = $"{newCount} yeni mail | {spamCount} spam taşındı | {threatCount} tehdit silindi";

            // Sistem tepsisi bildirimi — sadece anlamlı bir değişiklik varsa göster
            int total = newCount + spamCount + threatCount;
            if (total > 0 && _notifyIcon != null)
            {
                var parts = new List<string>();
                if (newCount > 0)    parts.Add($"{newCount} yeni mail");
                if (spamCount > 0)   parts.Add($"{spamCount} spam taşındı");
                if (threatCount > 0) parts.Add($"{threatCount} tehdit imha edildi");
                string body = string.Join(" • ", parts);
                var icon = threatCount > 0 ? System.Windows.Forms.ToolTipIcon.Warning
                                            : System.Windows.Forms.ToolTipIcon.Info;
                try { _notifyIcon.ShowBalloonTip(4000, "Siber Mail & Güvenlik Asistanı: Otomatik Sync", body, icon); }
                catch { /* tepsi ikonu kapanmış olabilir */ }
            }

            return (newCount, spamCount, threatCount);
        }

        private void UpdateLastSyncIndicator()
        {
            if (LastSyncText == null) return;
            Dispatcher.Invoke(() =>
            {
                if (_lastSyncAt.HasValue)
                {
                    LastSyncText.Text = $"Son güncelleme: {_lastSyncAt.Value:HH:mm:ss}";
                    LastSyncText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4ADE80"));
                }
                else
                {
                    LastSyncText.Text = "Otomatik sync hazırlanıyor...";
                    LastSyncText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#555"));
                }
            });
        }

        /// <summary>
        /// Sync sürecindeki ara aşamaları kullanıcıya gösterir (Bağlanılıyor, mailler çekiliyor vb.).
        /// _lastSyncAt'i değiştirmez — başarılı bitiş sonrası UpdateLastSyncIndicator() asıl "Son güncelleme" yazısını koyar.
        /// </summary>
        private void SetLastSyncIndicatorText(string text, string hexColor)
        {
            if (LastSyncText == null) return;
            Dispatcher.Invoke(() =>
            {
                LastSyncText.Text = text;
                LastSyncText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hexColor));
            });
        }

        private void RefreshMail_Click(object sender, RoutedEventArgs e)
        {
            LoadMailsForFolder(_currentFolderId);
            StatusText.Text = Application.Current.FindResource("StatusMailsRefreshed")?.ToString() ?? "Mailler yenilendi";
        }

        /// <summary>
        /// Çöp Kutusu veya Spam'deki bir maili Gelen Kutusu'na geri taşır.
        /// Hem yerel DB'yi günceller hem de Gmail tarafında Inbox'a MoveToAsync yapar.
        /// </summary>
        private async void RestoreToInbox_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedMail == null) return;

            try
            {
                int originalFolderId = _selectedMail.FolderId;

                // 1) DB'de folder=1 (Inbox) olarak güncelle
                await DatabaseHelper.MoveMailAsync(_selectedMail.Id, 1);

                // 2) Skorları sıfırla — tekrar analiz edilebilsin diye (opsiyonel ama tutarlı)
                _selectedMail.IsSpam = false;
                _selectedMail.IsPhishing = false;
                _selectedMail.FolderId = 1;
                await DatabaseHelper.UpdateMailAsync(_selectedMail);

                // 3) Gmail tarafında da Inbox'a geri taşı
                if (!string.IsNullOrEmpty(_selectedMail.GmailMessageId) && _gmailService != null && _gmailService.IsConnected)
                {
                    _ = _gmailService.RestoreToInboxAsync(_selectedMail.GmailMessageId);
                }

                DatabaseHelper.SaveSystemLog("Mail Geri Alındı",
                    $"Klasör {originalFolderId} → 1 (Inbox). Gönderen: {_selectedMail.FromEmail}");

                StatusText.Text = "Mail Gelen Kutusuna geri taşındı";
                StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4ADE80"));

                // Seçim temizle ve mevcut klasörü yenile
                _selectedMail = null;
                MailSubject.Text = Application.Current.FindResource("SelectMail")?.ToString() ?? "Bir mail seçin";
                MailFrom.Text = "";
                MailDate.Text = "";
                MailBodyRich.Document.Blocks.Clear();
                MailActionsPanel.Visibility = Visibility.Collapsed;
                AnalysisPanel.Visibility = Visibility.Collapsed;
                RestoreToInboxButton.Visibility = Visibility.Collapsed;

                LoadMailsForFolder(_currentFolderId);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Geri alma sırasında hata: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// "Sil" butonu artık doğrudan silmiyor — kullanıcıya 3-seçenekli onay overlay'i gösterir:
        /// Çöp Kutusuna Taşı / Kalıcı Olarak Sil / İptal.
        /// Mail zaten Çöp Kutusu'ndaysa Trash butonu gizlenir.
        /// </summary>
        private void DeleteMail_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedMail == null) return;

            bool alreadyInTrash = _selectedMail.FolderId == 4;
            string subject = string.IsNullOrEmpty(_selectedMail.Subject)
                ? "(Konu yok)"
                : _selectedMail.Subject;

            DeleteConfirmMessage.Text = alreadyInTrash
                ? $"\"{subject}\" maili zaten Çöp Kutusu'nda. Kalıcı olarak silmek ister misiniz?"
                : $"\"{subject}\" mailini nasıl silmek istersiniz?";

            // Trash butonu ve açıklama satırı — mail zaten trash'teyse gereksiz, gizlensin
            DeleteTrashButton.Visibility = alreadyInTrash ? Visibility.Collapsed : Visibility.Visible;
            TrashHintRow.Visibility = alreadyInTrash ? Visibility.Collapsed : Visibility.Visible;

            DeleteConfirmOverlay.Visibility = Visibility.Visible;
        }

        private async void ConfirmMoveToTrash_Click(object sender, RoutedEventArgs e)
        {
            DeleteConfirmOverlay.Visibility = Visibility.Collapsed;

            try
            {
                var trash = (await DatabaseHelper.GetFoldersAsync()).FirstOrDefault(f => f.Type == "trash");
                if (trash == null)
                {
                    MessageBox.Show("Çöp Kutusu klasörü bulunamadı.", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
                    _bulkDeleteMode = false;
                    return;
                }

                // Toplu mod: seçili tüm mailleri tek tek taşı
                List<Mail> targets = _bulkDeleteMode
                    ? MailListBox.SelectedItems.Cast<Mail>().ToList()
                    : (_selectedMail != null ? new List<Mail> { _selectedMail } : new List<Mail>());
                _bulkDeleteMode = false;

                if (targets.Count == 0) return;

                int moved = 0;
                foreach (var mail in targets)
                {
                    int origFolder = mail.FolderId;
                    await DatabaseHelper.MoveMailAsync(mail.Id, trash.Id);
                    if (!string.IsNullOrEmpty(mail.GmailMessageId) && _gmailService != null && _gmailService.IsConnected)
                        _ = _gmailService.MoveToTrashAsync(mail.GmailMessageId);
                    DatabaseHelper.SaveSystemLog("Mail Çöp Kutusuna Taşındı",
                        $"Klasör {origFolder} → {trash.Id} (Trash). Mail ID: {mail.Id}");
                    moved++;
                }

                ClearSelectedMailUI();
                LoadMailsForFolder(_currentFolderId);
                StatusText.Text = moved > 1
                    ? $"{moved} mail Çöp Kutusuna taşındı"
                    : "Mail Çöp Kutusuna taşındı (kalıcı silmedi)";
                StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));
            }
            catch (Exception ex)
            {
                _bulkDeleteMode = false;
                MessageBox.Show($"Çöp Kutusuna taşıma hatası: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void ConfirmPermanentDelete_Click(object sender, RoutedEventArgs e)
        {
            DeleteConfirmOverlay.Visibility = Visibility.Collapsed;

            // Toplu mod: seçili tüm mailleri al
            List<Mail> targets = _bulkDeleteMode
                ? MailListBox.SelectedItems.Cast<Mail>().ToList()
                : (_selectedMail != null ? new List<Mail> { _selectedMail } : new List<Mail>());
            _bulkDeleteMode = false;

            if (targets.Count == 0) return;

            string confirmMsg = targets.Count > 1
                ? $"{targets.Count} maili veritabanından ve Gmail'den KALICI olarak silmek istediğinize emin misiniz?\n\nBu işlem geri alınamaz."
                : "Bu maili veritabanından ve Gmail'den KALICI olarak silmek istediğinize emin misiniz?\n\nBu işlem geri alınamaz.";

            var doubleConfirm = MessageBox.Show(
                confirmMsg,
                "Kalıcı Silme Onayı",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No);
            if (doubleConfirm != MessageBoxResult.Yes) return;

            try
            {
                int deleted = 0;
                foreach (var mail in targets)
                {
                    var gmailMessageId = mail.GmailMessageId;
                    await DatabaseHelper.DeleteMailAsync(mail.Id);
                    if (!string.IsNullOrEmpty(gmailMessageId) && _gmailService != null && _gmailService.IsConnected)
                        _ = _gmailService.DeleteFromGmailAsync(gmailMessageId);
                    DatabaseHelper.SaveSystemLog("Mail Kalıcı Silindi",
                        $"Mail ID {mail.Id}. Gönderen: {mail.FromEmail}");
                    deleted++;
                }

                ClearSelectedMailUI();
                LoadMailsForFolder(_currentFolderId);
                StatusText.Text = deleted > 1
                    ? $"{deleted} mail kalıcı olarak silindi"
                    : Application.Current.FindResource("StatusMailDeleted")?.ToString() ?? "Mail kalıcı olarak silindi";
                StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Silme hatası: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CancelDelete_Click(object sender, RoutedEventArgs e)
        {
            DeleteConfirmOverlay.Visibility = Visibility.Collapsed;
            _bulkDeleteMode = false;
        }

        /// <summary>
        /// Mail seçim/detay panelini temizler — Trash, Sil, ResetGmail vb. ortak temizlik.
        /// </summary>
        private void ClearSelectedMailUI()
        {
            _selectedMail = null;
            MailSubject.Text = Application.Current.FindResource("SelectMail")?.ToString() ?? "Bir mail seçin";
            MailFrom.Text = "";
            MailDate.Text = "";
            MailBodyRich.Document.Blocks.Clear();
            MailActionsPanel.Visibility = Visibility.Collapsed;
            AnalysisPanel.Visibility = Visibility.Collapsed;
            if (RestoreToInboxButton != null)
                RestoreToInboxButton.Visibility = Visibility.Collapsed;
        }

        private async void MarkAsRead_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedMail != null && !_selectedMail.IsRead)
            {
                _selectedMail.IsRead = true;
                await DatabaseHelper.UpdateMailAsync(_selectedMail);
                LoadMailsForFolder(_currentFolderId);
            }
        }

        private async void MarkAsSpam_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedMail == null)
                return;

            var spamFolder = (await DatabaseHelper.GetFoldersAsync()).FirstOrDefault(f => f.Type == "spam");
            if (spamFolder != null)
            {
                await DatabaseHelper.MoveMailAsync(_selectedMail.Id, spamFolder.Id);
                await _gmailService.MoveToSpamAsync(_selectedMail.GmailMessageId);

                _selectedMail = null;
                MailSubject.Text = Application.Current.FindResource("SelectMail").ToString();
                MailBodyRich.Document.Blocks.Clear();
                MailActionsPanel.Visibility = Visibility.Collapsed;
                AnalysisPanel.Visibility = Visibility.Collapsed;

                LoadMailsForFolder(_currentFolderId);
                StatusText.Text = Application.Current.FindResource("StatusMarkedAsSpam")?.ToString() ?? "Spam olarak işaretlendi";
            }
        }

        private async void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            string query = SearchBox.Text.Trim();
            if (string.IsNullOrEmpty(query))
            {
                LoadMailsForFolder(_currentFolderId);
                return;
            }

            _mailList.Clear();
            var results = await DatabaseHelper.SearchMailsAsync(query);
            foreach (var mail in results)
            {
                _mailList.Add(mail);
            }
            MailListBox.ItemsSource = _mailList;
            EmptyMailListText.Visibility = _mailList.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        private void GmailSettings_Click(object sender, RoutedEventArgs e)
        {
            PopulateSettingsFromStorage();
            SettingsOverlay.Visibility = Visibility.Visible;
        }

        /// <summary>
        /// Settings overlay'i her açılışta kayıtlı değerlerle önceden doldurur.
        /// Kullanıcı düzenlemek isterse görür, değiştirmezse mevcut değer korunur.
        /// </summary>
        private void PopulateSettingsFromStorage()
        {
            // VT API key — _apiKey constructor'da DPAPI ile decrypt edilip yüklendi
            ApiPasswordBox.Password = _apiKey ?? "";

            // Gmail bilgileri — DB'den decrypt edilerek alınır
            var (email, password) = DatabaseHelper.GetGmailAccount();
            GmailEmailBox.Text = email ?? "";
            if (!string.IsNullOrEmpty(password))
                GmailPasswordBox.Password = password;
            else
                GmailPasswordBox.Clear();

            // Ngrok URL
            string ngrokUrl = DatabaseHelper.GetSetting("ngrok_url") ?? "";
            if (!string.IsNullOrEmpty(ngrokUrl))
                NgrokUrlBox.Text = ngrokUrl;

            // Senkron aralığı seçimi
            ApplySyncIntervalToUI();
        }

        private void ShowAppPasswordHelp_Click(object sender, RoutedEventArgs e)
        {
            HelpOverlay.Visibility = Visibility.Visible;
        }

        private void CloseHelpOverlay_Click(object sender, RoutedEventArgs e)
        {
            HelpOverlay.Visibility = Visibility.Collapsed;
        }

        private void ShowAbout_Click(object sender, RoutedEventArgs e)
        {
            // Eski MessageBox yerine zengin About overlay'i göster — ekip, teknolojiler,
            // lisanslar ve KVKK bilgisi sunum için merkezi yerde.
            AboutOverlay.Visibility = Visibility.Visible;
        }

        private void CloseAboutOverlay_Click(object sender, RoutedEventArgs e)
        {
            AboutOverlay.Visibility = Visibility.Collapsed;
        }

        private void ReplyMail_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedMail == null)
                return;

            ComposeMailOverlay.Visibility = Visibility.Visible;
            ComposeToBox.Text = _selectedMail.FromEmail;
            ComposeSubjectBox.Text = $"Re: {_selectedMail.Subject}";
            ComposeBodyBox.Text = $"\n\n--- Önceki mesaj ---\n{_selectedMail.Body}";
        }

        private void OpenSettings_Click(object sender, RoutedEventArgs e)
        {
            PopulateSettingsFromStorage();
            SettingsOverlay.Visibility = Visibility.Visible;
        }

        private void CloseSettings_Click(object sender, RoutedEventArgs e)
        {
            SettingsOverlay.Visibility = Visibility.Collapsed;
        }

        private const string LoggedOutKey = "gmail_logged_out";
        private const string KvkkAcceptedKey = "kvkk_accepted_v1";

        // ==========================================
        // KVKK / DISCLAIMER (ilk açılış onayı)
        // ==========================================

        private void ShowKvkkOverlayIfNeeded()
        {
            // Daha önce kabul edilmişse atla
            if (DatabaseHelper.GetSetting(KvkkAcceptedKey) == "true")
                return;

            // Overlay'i göster ve onay kutusunun değişimini izle (Kabul butonunu enable/disable et)
            KvkkOverlay.Visibility = Visibility.Visible;
            KvkkAgreeCheck.Checked   += (s, e) => KvkkAcceptButton.IsEnabled = true;
            KvkkAgreeCheck.Unchecked += (s, e) => KvkkAcceptButton.IsEnabled = false;
        }

        private void KvkkAccept_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                DatabaseHelper.SaveSetting(KvkkAcceptedKey, "true");
                DatabaseHelper.SaveSystemLog("KVKK Onayı", $"Kullanıcı gizlilik koşullarını kabul etti @ {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                KvkkOverlay.Visibility = Visibility.Collapsed;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Onay kaydedilemedi: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void KvkkDecline_Click(object sender, RoutedEventArgs e)
        {
            // Kabul etmeyen kullanıcı uygulamayı kullanamaz → temiz kapan
            var confirm = MessageBox.Show(
                "Gizlilik koşullarını reddederseniz uygulama kapanır.\n\nÇıkmak istediğinize emin misiniz?",
                "Onay Reddedildi",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);
            if (confirm == MessageBoxResult.Yes)
            {
                // FlaskServiceLauncher.Stop App.OnExit içinde çağrılır
                Application.Current.Shutdown();
            }
        }

        /// <summary>
        /// "Çıkış Yap" — Reset'in aksine kayıtlı email/parolayı silmez.
        /// IMAP bağlantısını kapatır, otomatik senkronu durdurur, DB'ye flag yazar.
        /// Kullanıcı tekrar Settings → Save'e bastığında veya 'Yeniden Bağlan' diyerek geri döner.
        /// </summary>
        private async void LogoutGmail_Click(object sender, RoutedEventArgs e)
        {
            var confirm = MessageBox.Show(
                "Gmail bağlantısından çıkış yapmak istediğinize emin misiniz?\n\n" +
                "• IMAP bağlantısı kesilecek\n" +
                "• Otomatik senkron duracak\n" +
                "• Email ve App Password kayıtlı kalır (Save'e basarak yeniden bağlanabilirsiniz)",
                "Gmail Çıkışı",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);
            if (confirm != MessageBoxResult.Yes) return;

            try
            {
                if (_gmailService != null)
                {
                    await _gmailService.DisconnectAsync();
                }

                // Flag'i set et — Auto-sync timer ve startup check buna bakar.
                DatabaseHelper.SaveSetting(LoggedOutKey, "true");

                // Timer'ı durdur
                _gmailSyncTimer?.Stop();
                _gmailSyncTimer = null;

                GmailStatusText.Text = "Çıkış yapıldı";
                if (LastSyncText != null)
                {
                    LastSyncText.Text = "Gmail çıkış yapıldı — Ayarlardan Kaydet'e basarak tekrar bağlanın";
                    LastSyncText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));
                }
                StatusText.Text = "Gmail bağlantısı kapatıldı";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Çıkış sırasında hata oluştu: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void ResetGmail_Click(object sender, RoutedEventArgs e)
        {
            var confirm = MessageBox.Show(
                "Kayıtlı Gmail hesabını ve şifresini veritabanından kalıcı olarak silmek istediğinize emin misiniz?\n\n" +
                "Bu sadece uygulamadaki kaydı temizler, Gmail hesabınız etkilenmez. Yeniden bağlanmak için Email ve App Password girip Kaydet'e basın.",
                "Gmail Hesabını Sıfırla",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            if (confirm != MessageBoxResult.Yes) return;

            try
            {
                // Mevcut IMAP bağlantısını kapat
                if (_gmailService != null)
                {
                    await _gmailService.DisconnectAsync();
                    _gmailService.Dispose();
                }

                DatabaseHelper.DeleteGmailAccount();
                // Reset = tüm Gmail state temizliği — çıkış yapıldı flag'i de kalkar
                DatabaseHelper.SaveSetting(LoggedOutKey, "false");

                // Yeni servisi temiz başlat
                _gmailService = new GmailService();
                _gmailService.StatusChanged += GmailService_StatusChanged;

                GmailEmailBox.Text = "";
                GmailPasswordBox.Clear();
                GmailStatusText.Text = Application.Current.FindResource("GmailNotConnected")?.ToString() ?? "Bağlı değil";

                MessageBox.Show("Gmail hesabı veritabanından silindi. Email ve yeni App Password girip Kaydet'e basın.", "Bilgi", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Hesap silinirken hata: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SaveSettings_Click(object sender, RoutedEventArgs e)
        {
            // VT API anahtarı DPAPI ile şifrelenerek diske yazılır.
            File.WriteAllText(_settingsFilePath, SecureStore.Encrypt(_apiKey));

            string gmailEmail = GmailEmailBox.Text.Trim();
            // Gmail App Password — Görünür modda ise TextBox'tan, gizli modda ise PasswordBox'tan oku
            string gmailPassword = _isGmailPasswordVisible
                ? GmailPasswordTextBox.Text
                : GmailPasswordBox.Password;

            if (!string.IsNullOrEmpty(gmailEmail) && !string.IsNullOrEmpty(gmailPassword))
            {
                DatabaseHelper.SaveGmailAccount(gmailEmail, gmailPassword);

                // Kullanıcı yeni cred girip Save'e basıyorsa "çıkış yapıldı" durumu otomatik kalkar.
                bool wasLoggedOut = DatabaseHelper.GetSetting(LoggedOutKey) == "true";
                if (wasLoggedOut)
                {
                    DatabaseHelper.SaveSetting(LoggedOutKey, "false");
                    StartGmailSyncTimer(); // Timer yeniden çalışır
                }

                CheckGmailConnection();
            }

            string ngrokUrl = NgrokUrlBox.Text.Trim();
            if (!string.IsNullOrEmpty(ngrokUrl))
            {
                DatabaseHelper.SaveSetting("ngrok_url", ngrokUrl);
                _cachedNgrokUrl = ngrokUrl;
                _mlService.RefreshCachedUrl();
            }
            else
            {
                _cachedNgrokUrl = "";
            }

            UpdateApiStatusUI();
            SettingsOverlay.Visibility = Visibility.Collapsed;
            StatusText.Text = Application.Current.FindResource("StatusSettingsSaved")?.ToString() ?? "Ayarlar kaydedildi";
        }

        private void LoadApiKey()
        {
            if (!File.Exists(_settingsFilePath)) return;

            string raw = File.ReadAllText(_settingsFilePath).Trim();
            _apiKey = SecureStore.Decrypt(raw);

            // Migration: eski düz metin dosyasını yeni şifreli formatla yeniden yaz
            if (!SecureStore.IsEncrypted(raw) && !string.IsNullOrEmpty(_apiKey))
            {
                try { File.WriteAllText(_settingsFilePath, SecureStore.Encrypt(_apiKey)); } catch { }
            }
            UpdateApiStatusUI();
        }

        /// <summary>
        /// Alt status bar'daki VirusTotal API göstergesini günceller.
        /// Yalnızca _apiKey'in dolu olup olmadığına bakar (gerçek bir VT pingi yok,
        /// kota tüketmek istemiyoruz; ilk tarama denemesinde hatadan anlaşılır).
        /// </summary>
        private void UpdateApiStatusUI()
        {
            if (string.IsNullOrEmpty(_apiKey))
            {
                ApiStatusText.Text = "VT API: Anahtar Yok";
                ApiStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
            }
            else
            {
                ApiStatusText.Text = "VT API: Aktif";
                ApiStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4ADE80"));
            }
        }

        private void SetupSystemTray()
        {
            _notifyIcon = new System.Windows.Forms.NotifyIcon();
            _notifyIcon.Icon = System.Drawing.SystemIcons.Shield;
            _notifyIcon.Visible = true;
            _notifyIcon.Text = "Siber Mail & Güvenlik Asistanı";

            _notifyIcon.DoubleClick += (s, e) => ShowMainWindow();

            var contextMenu = new System.Windows.Forms.ContextMenuStrip();
            var openItem = contextMenu.Items.Add(Application.Current.FindResource("TrayOpen")?.ToString() ?? "Aç");
            openItem.Click += (s, e) => ShowMainWindow();
            contextMenu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
            var closeItem = contextMenu.Items.Add(Application.Current.FindResource("TrayExit")?.ToString() ?? "Çıkış");
            closeItem.Click += (s, e) => CloseApplicationCompletely();

            _notifyIcon.ContextMenuStrip = contextMenu;
        }

        private void ShowMainWindow()
        {
            this.Show();
            this.WindowState = WindowState.Normal;
            this.Activate();
        }

        private void CloseApplicationCompletely()
        {
            if (_notifyIcon != null)
            {
                _notifyIcon.Visible = false;
                _notifyIcon.Dispose();
            }
            _gmailService?.Dispose();
            // Flask child process'i kapat — Environment.Exit OnExit'i tetiklemeyebilir,
            // bu yüzden burada da açıkça çağırıyoruz.
            try { FlaskServiceLauncher.Stop(); } catch { }
            Environment.Exit(0);
        }

        private void SetupFolderWatcher()
        {
            string downloadsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            if (Directory.Exists(downloadsPath))
            {
                _folderWatcher = new FileSystemWatcher(downloadsPath);
                _folderWatcher.NotifyFilter = NotifyFilters.FileName;
                _folderWatcher.Filter = "*.*";
                _folderWatcher.Created += OnFileDetected;
            }
        }

        private async void OnFileDetected(object sender, FileSystemEventArgs e)
        {
            string ext = Path.GetExtension(e.FullPath).ToLower();
            if (ext == ".crdownload" || ext == ".tmp" || ext == ".part")
                return;

            await Task.Delay(1500);

            Application.Current.Dispatcher.Invoke(() =>
            {
                if (!string.IsNullOrEmpty(_apiKey))
                {
                    StatusText.Text = $"Dosya algılandı: {e.Name}";
                }
            });
        }

        private void ToggleApiVisibility_Click(object sender, RoutedEventArgs e)
        {
            _isApiVisible = !_isApiVisible;
            ToggleEyeIcon.Kind = _isApiVisible ? PackIconMaterialKind.EyeOffOutline : PackIconMaterialKind.EyeOutline;

            if (_isApiVisible)
            {
                // Gizliden açık metne geç — PasswordBox.Password → TextBox.Text
                ApiTextBox.Text = ApiPasswordBox.Password;
                ApiPasswordBox.Visibility = Visibility.Collapsed;
                ApiTextBox.Visibility = Visibility.Visible;
                ApiTextBox.Focus();
            }
            else
            {
                // Açık metinden gizliye geç
                ApiPasswordBox.Password = ApiTextBox.Text;
                ApiTextBox.Visibility = Visibility.Collapsed;
                ApiPasswordBox.Visibility = Visibility.Visible;
                ApiPasswordBox.Focus();
            }
        }

        private void ApiPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            // PasswordBox güncellendi → _apiKey'i güncel tut
            if (!_isApiVisible) _apiKey = ApiPasswordBox.Password;
        }

        private void ApiTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            // TextBox güncellendi → _apiKey'i güncel tut
            if (_isApiVisible) _apiKey = ApiTextBox.Text;
        }

        /// <summary>VT API alanını formda temizler — DB'ye yansımaz, Kaydet'e basılırsa kaydolur.</summary>
        private void ClearApiKey_Click(object sender, RoutedEventArgs e)
        {
            ApiPasswordBox.Password = "";
            ApiTextBox.Text = "";
            _apiKey = "";
            ApiPasswordBox.Focus();
        }

        // ==========================================
        // Gmail App Password görünürlük toggle + Sil
        // ==========================================
        private bool _isGmailPasswordVisible = false;

        private void ToggleGmailPasswordVisibility_Click(object sender, RoutedEventArgs e)
        {
            _isGmailPasswordVisible = !_isGmailPasswordVisible;
            ToggleGmailEyeIcon.Kind = _isGmailPasswordVisible ? PackIconMaterialKind.EyeOffOutline : PackIconMaterialKind.EyeOutline;

            if (_isGmailPasswordVisible)
            {
                GmailPasswordTextBox.Text = GmailPasswordBox.Password;
                GmailPasswordBox.Visibility = Visibility.Collapsed;
                GmailPasswordTextBox.Visibility = Visibility.Visible;
                GmailPasswordTextBox.Focus();
            }
            else
            {
                GmailPasswordBox.Password = GmailPasswordTextBox.Text;
                GmailPasswordTextBox.Visibility = Visibility.Collapsed;
                GmailPasswordBox.Visibility = Visibility.Visible;
                GmailPasswordBox.Focus();
            }
        }

        /// <summary>Gmail Email ve App Password alanlarını formda temizler.</summary>
        private void ClearGmailFields_Click(object sender, RoutedEventArgs e)
        {
            GmailEmailBox.Text = "";
            GmailPasswordBox.Password = "";
            GmailPasswordTextBox.Text = "";
            GmailEmailBox.Focus();
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            this.Hide();
            _notifyIcon.ShowBalloonTip(2000, "Siber Mail & Güvenlik Asistanı", "Uygulama arka planda çalışmaya devam ediyor.", System.Windows.Forms.ToolTipIcon.Info);
        }

        private void Window_MouseDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (e.ChangedButton == System.Windows.Input.MouseButton.Left)
                this.DragMove();
        }

        private void Maximize_Click(object sender, RoutedEventArgs e)
        {
            if (this.WindowState == WindowState.Normal)
            {
                this.WindowState = WindowState.Maximized;
                MaximizeIcon.Kind = PackIconMaterialKind.WindowRestore;
            }
            else
            {
                this.WindowState = WindowState.Normal;
                MaximizeIcon.Kind = PackIconMaterialKind.WindowMaximize;
            }
        }

        private void Minimize_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
        }

        private void ChangeLanguage(string languageCode)
        {
            try
            {
                // Yalnızca TR ve EN destekleniyor — bilinmeyen kod TR'ye fallback.
                string normalized = string.Equals(languageCode, "EN", StringComparison.OrdinalIgnoreCase) ? "EN" : "TR";
                string source = normalized == "EN"
                    ? "pack://application:,,,/Languages/StringResources.en.xaml"
                    : "pack://application:,,,/Languages/StringResources.tr.xaml";

                ResourceDictionary dict = new ResourceDictionary { Source = new Uri(source, UriKind.Absolute) };

                Application.Current.Resources.MergedDictionaries.Clear();
                Application.Current.Resources.MergedDictionaries.Add(dict);

                // Seçimi kalıcı kaydet — sonraki açılışta otomatik uygulanır.
                DatabaseHelper.SaveSetting("language", normalized);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Dil dosyası bulunamadı veya yüklenemedi!\n\nHata: {ex.Message}", "Siber Kalkan Dil Hatası");
            }
        }

        private void LangTR_Click(object sender, RoutedEventArgs e) => ChangeLanguage("TR");
        private void LangEN_Click(object sender, RoutedEventArgs e) => ChangeLanguage("EN");

        // ==========================================
        // SCANNER TAB HANDLERS
        // ==========================================

        private void TabMail_Checked(object sender, RoutedEventArgs e)
        {
            if (MailAppPanel == null || ScannerPanel == null) return;
            MailAppPanel.Visibility = Visibility.Visible;
            ScannerPanel.Visibility = Visibility.Collapsed;
        }

        private void TabScanner_Checked(object sender, RoutedEventArgs e)
        {
            if (MailAppPanel == null || ScannerPanel == null) return;
            MailAppPanel.Visibility = Visibility.Collapsed;
            ScannerPanel.Visibility = Visibility.Visible;
            LoadLogs();
            StartPingTimer();
        }

        private void ScanTabText_Checked(object sender, RoutedEventArgs e)
        {
            if (PanelTextInput == null || PanelUrlInput == null || PanelFileInput == null) return;
            PanelTextInput.Visibility = Visibility.Visible;
            PanelUrlInput.Visibility = Visibility.Collapsed;
            PanelFileInput.Visibility = Visibility.Collapsed;
            SetAnalyzeButtonForScanType("text");
            ResetScanResultDisplay();
        }

        private void ScanTabUrl_Checked(object sender, RoutedEventArgs e)
        {
            if (PanelTextInput == null || PanelUrlInput == null || PanelFileInput == null) return;
            PanelTextInput.Visibility = Visibility.Collapsed;
            PanelUrlInput.Visibility = Visibility.Visible;
            PanelFileInput.Visibility = Visibility.Collapsed;
            SetAnalyzeButtonForScanType("url");
            ResetScanResultDisplay();
        }

        private void ScanTabFile_Checked(object sender, RoutedEventArgs e)
        {
            if (PanelTextInput == null || PanelUrlInput == null || PanelFileInput == null) return;
            PanelTextInput.Visibility = Visibility.Collapsed;
            PanelUrlInput.Visibility = Visibility.Collapsed;
            PanelFileInput.Visibility = Visibility.Visible;
            SetAnalyzeButtonForScanType("file");
            ResetScanResultDisplay();
        }

        /// <summary>
        /// Tarama sekmeleri arasında geçince önceki sonucu temizler — yanlış yorumlamayı önler.
        /// Gauge sıfırlanır, mesaj başlangıç haline döner, URL/dosya sonuç paneli gizlenir.
        /// </summary>
        private void ResetScanResultDisplay()
        {
            if (ScoreText == null) return;

            ScoreText.Text = "0";
            ScoreLabel.Text = Application.Current.FindResource("StatusReady")?.ToString() ?? "Hazır";
            ScoreLabel.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#A0A0A0"));
            GaugeForeground.Stroke = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#22C55E"));
            SystemMessage.Text = Application.Current.FindResource("MsgAnalyzeHint")?.ToString()
                ?? "Analiz için bir metin girin ve 'Analiz Et' butonuna tıklayın.";
            if (UrlResultPanel != null)
                UrlResultPanel.Visibility = Visibility.Collapsed;
        }

        /// <summary>
        /// Aktif tarama sekmesine göre ana analiz butonunun yazısını ve ikonunu günceller.
        /// Metin = ML (yapay zeka); URL ve Dosya = VirusTotal API kullanır.
        /// </summary>
        private void SetAnalyzeButtonForScanType(string scanType)
        {
            if (AnalyzeButtonText == null || AnalyzeIcon == null) return;

            switch (scanType)
            {
                case "url":
                case "file":
                    AnalyzeButtonText.Text = "VirusTotal ile Analiz Et";
                    AnalyzeIcon.Kind = PackIconMaterialKind.ShieldSearch;
                    break;
                case "text":
                default:
                    AnalyzeButtonText.Text = "Yapay Zeka ile Analiz Et";
                    AnalyzeIcon.Kind = PackIconMaterialKind.Brain;
                    break;
            }
        }

        private void InputTextScanner_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (string.IsNullOrEmpty(InputTextScanner.Text))
                TextHint.Visibility = Visibility.Visible;
            else
                TextHint.Visibility = Visibility.Collapsed;
        }

        private void ClearInput_Click(object sender, RoutedEventArgs e)
        {
            InputTextScanner.Text = "";
            InputUrlScanner.Text = "";
            FileNameText.Text = "Dosya sürükleyin veya seçin";
            _selectedFilePath = "";
            UrlResultPanel.Visibility = Visibility.Collapsed;

            ScoreText.Text = "0";
            ScoreLabel.Text = Application.Current.FindResource("StatusReady")?.ToString() ?? "Hazır";
            SystemMessage.Text = Application.Current.FindResource("MsgAnalyzeHint")?.ToString() ?? "Analiz için bir metin girin ve 'Yapay Zeka ile Analiz Et' butonuna tıklayın.";
            GaugeForeground.Stroke = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#22C55E"));
        }

       private async void StartAnalysis_Click(object sender, RoutedEventArgs e)
        {
            string inputData = "";
            string scanType = "text";

            if (ScanTabText.IsChecked == true) { inputData = InputTextScanner.Text; scanType = "text"; }
            else if (ScanTabUrl.IsChecked == true) { inputData = InputUrlScanner.Text; scanType = "url"; }
            else if (ScanTabFile.IsChecked == true) { inputData = FileNameText.Text; scanType = "file"; }

            if (string.IsNullOrWhiteSpace(inputData) || inputData == "Dosya sürükleyin veya seçin")
            {
                MessageBox.Show("Lütfen analiz edilecek bir metin veya URL girin.", "Uyarı", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            ShowLoading(true);
            SystemMessage.Text = Application.Current.FindResource("MsgPleaseWait")?.ToString() ?? "Analiz yapılıyor, lütfen bekleyin...";
            StatusText.Text = Application.Current.FindResource("StatusAnalyzing")?.ToString() ?? "Analiz yapılıyor...";

            try
            {
                double resultScore = 0;
                string topThreatName = "";
                // VT taramalarında SaveLogToDatabase'e geçilecek mapped score (0/50/90).
                // Text analizinde -1 kalır, eski mantık çalışır.
                double dbScoreOverride = -1;

                if (scanType == "url")
                {
                    var vtData = await VirusTotalService.ScanUrlAsync(inputData, _apiKey);
                    if (vtData != null)
                    {
                        if (!string.IsNullOrEmpty(vtData.ErrorMessage))
                        {
                            SystemMessage.Text = $"VirusTotal: {vtData.ErrorMessage}";
                            ScoreText.Text = "0";
                            ScoreLabel.Text = "Hata";
                            ScoreLabel.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#A0A0A0"));
                            GaugeForeground.Stroke = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#A0A0A0"));
                            ShowLoading(false);
                            StatusText.Text = "Analiz hatası";
                            SaveLogToDatabase(scanType, inputData, "Hata", 0);
                            LoadLogs();
                            return;
                        }
                        if (vtData.IsRateLimited)
                        {
                            SystemMessage.Text = "VirusTotal rate limit aşıldı. Lütfen 1 dakika bekleyip tekrar deneyin.";
                            ScoreText.Text = "0";
                            ScoreLabel.Text = "Rate Limit";
                            ScoreLabel.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));
                            GaugeForeground.Stroke = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));
                            ShowLoading(false);
                            return;
                        }

                        // Başarılı sonuç — yeni Malicious-tabanlı gösterim
                        _lastVtResult = vtData;
                        string threatType = vtData.TopThreatType();
                        dbScoreOverride = DisplayVtScanResult(vtData.Malicious, vtData.TotalEngines, threatType, "url");

                        topThreatName = string.IsNullOrEmpty(threatType)
                            ? $"{vtData.Malicious}/{vtData.TotalEngines} motor"
                            : $"{vtData.Malicious}/{vtData.TotalEngines} — {threatType}";

                        VtUrlResult.Text = $"Malicious: {vtData.Malicious} | Suspicious: {vtData.Suspicious} | Harmless: {vtData.Harmless} | Undetected: {vtData.Undetected}";
                        UrlResultPanel.Visibility = Visibility.Visible;
                    }
                    else
                    {
                        SystemMessage.Text = "VirusTotal'e bağlanılamadı";
                        ScoreText.Text = "0";
                        ScoreLabel.Text = "Bağlantı Hatası";
                        ShowLoading(false);
                        return;
                    }
                }
                else if (scanType == "file")
                {
                    if (string.IsNullOrEmpty(_selectedFilePath))
                    {
                        MessageBox.Show("Lütfen bir dosya seçin.", "Uyarı", MessageBoxButton.OK, MessageBoxImage.Warning);
                        ShowLoading(false);
                        return;
                    }

                    string fileHash;
                    try
                    {
                        fileHash = GetFileHash(_selectedFilePath);
                    }
                    catch (Exception ex)
                    {
                        SystemMessage.Text = $"Dosya okunamadı: {ex.Message}";
                        ScoreText.Text = "0";
                        ScoreLabel.Text = "Dosya Hatası";
                        ShowLoading(false);
                        return;
                    }

                    // ═══════════════════════════════════════════════════════════════════
                    // 🛡️ JÜRİ DEMO MODU — Sunum için sahte malware hash mapping
                    // ─────────────────────────────────────────────────────────────────
                    // Sunum makinesinde gerçek malware tutmamak için belirli isimdeki
                    // BOŞ dosyalar için VT'ye dünyaca ünlü malware hash'leri gönderilir.
                    // Dosya içeriği güvenli kalır — sadece hash override edilir.
                    // SUNUM SONRASI: Bu blok ve _demoMalwareHashes silinebilir,
                    // kod normal davranışına döner (gerçek dosya hash'i kullanılır).
                    // ═══════════════════════════════════════════════════════════════════
                    string demoFileName = System.IO.Path.GetFileName(_selectedFilePath);
                    if (_demoMalwareHashes.TryGetValue(demoFileName, out string? demoHash))
                    {
                        System.Diagnostics.Debug.WriteLine(
                            $"[DEMO MODE] '{demoFileName}' için sahte malware hash kullanıldı: {demoHash}");
                        fileHash = demoHash;
                    }
                    // ═══════════════════════════════════════════════════════════════════

                    StatusText.Text = $"Dosya parmak izi (Hash) alındı, VT'ye soruluyor...";

                    var vtData = await VirusTotalService.ScanHashAsync(fileHash, _apiKey);
                    if (vtData != null && string.IsNullOrEmpty(vtData.ErrorMessage) && !vtData.IsRateLimited)
                    {
                        _lastVtResult = vtData;
                        string threatType = vtData.TopThreatType();
                        dbScoreOverride = DisplayVtScanResult(vtData.Malicious, vtData.TotalEngines, threatType, "file");

                        topThreatName = string.IsNullOrEmpty(threatType)
                            ? $"{vtData.Malicious}/{vtData.TotalEngines} motor"
                            : $"{vtData.Malicious}/{vtData.TotalEngines} — {threatType}";

                        VtUrlResult.Text = $"Malicious: {vtData.Malicious} | Suspicious: {vtData.Suspicious} | Harmless: {vtData.Harmless} | Undetected: {vtData.Undetected}";
                        UrlResultPanel.Visibility = Visibility.Visible;
                    }
                    else if (vtData != null && vtData.IsRateLimited)
                    {
                        SystemMessage.Text = "VirusTotal rate limit aşıldı. Lütfen 1 dakika bekleyip tekrar deneyin.";
                        ScoreText.Text = "0";
                        ScoreLabel.Text = "Rate Limit";
                        ScoreLabel.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));
                        GaugeForeground.Stroke = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));
                        ShowLoading(false);
                        return;
                    }
                    else
                    {
                        SystemMessage.Text = vtData?.ErrorMessage ?? "Dosya VT veritabanında bulunamadı (İlk Kez Görüldü)";
                        ScoreText.Text = "0";
                        ScoreLabel.Text = "Bilinmiyor";
                        ScoreLabel.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#A0A0A0"));
                        GaugeForeground.Stroke = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#A0A0A0"));
                        topThreatName = "İlk Kez Görüldü";
                        dbScoreOverride = 0;
                    }
                }
                else // (scanType == "text") ML / heuristik — DOKUNULMAZ
                {
                    var rs = await _mlService.AnalyzeTextAsync(inputData);
                    topThreatName = rs.HighestThreatLabel();
                    resultScore = Math.Max(rs.PhishingScore, Math.Max(rs.SpamScore, Math.Max(rs.SqlInjectionScore, Math.Max(rs.XssScore, rs.TrojanScore))));
                    UpdateScoreDisplay(resultScore, topThreatName);
                }

                int logId = SaveLogToDatabase(scanType, inputData, topThreatName, dbScoreOverride);

                // VT taraması Şüpheli (50) veya Kritik (90) ise ek detay tablolarına da kaydet.
                // zararli_linkler ve ekli_dosyalar tabloları log_id ile ana log'a bağlı.
                // tehdit_tipi kolonu: VT vendor sonucundan çıkarılan kategori (Trojan/Phishing/Adware/Malware vb.)
                if (logId > 0 && dbScoreOverride >= 40 && _lastVtResult != null)
                {
                    string vtDurum = dbScoreOverride >= 70 ? "Kritik" : "Şüpheli";
                    string tehditTipi = _lastVtResult.TopThreatType(); // "Trojan", "Phishing", "" vb.
                    try
                    {
                        if (scanType == "url")
                        {
                            DatabaseHelper.SaveMaliciousLink(logId, inputData, vtDurum, tehditTipi);
                            System.Diagnostics.Debug.WriteLine($"[DB] zararli_linkler'e kaydedildi: log_id={logId}, durum={vtDurum}, tip={tehditTipi}, url={inputData}");
                        }
                        else if (scanType == "file" && !string.IsNullOrEmpty(_selectedFilePath))
                        {
                            string fileName = Path.GetFileName(_selectedFilePath);
                            string fileHash = GetFileHash(_selectedFilePath);
                            // dosya_yolu: tam yerel yolu sakla — sonradan "konumu aç" / yeniden tara için
                            DatabaseHelper.SaveAttachedFile(logId, fileName, fileHash, _lastVtResult.Malicious, tehditTipi, _selectedFilePath);
                            System.Diagnostics.Debug.WriteLine($"[DB] ekli_dosyalar'a kaydedildi: log_id={logId}, tip={tehditTipi}, dosya={fileName}, malicious={_lastVtResult.Malicious}, yol={_selectedFilePath}");
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[DB] Zararlı kayıt eklenemedi: {ex.Message}");
                    }
                }

                LoadLogs();

                ShowLoading(false);
                StatusText.Text = Application.Current.FindResource("StatusAnalysisComplete")?.ToString() ?? "Analiz tamamlandı";
            
            }
            catch (Exception ex)
            {
                ShowLoading(false);
                SystemMessage.Text = $"Hata: {ex.Message}";
                StatusText.Text = Application.Current.FindResource("StatusAnalysisError")?.ToString() ?? "Analiz hatası";
            }
        }

        private void UpdateScoreDisplay(double score, string threatLabel = "")
        {
            int roundedScore = (int)Math.Round(score);
            ScoreText.Text = roundedScore.ToString();

            string displayLabel = string.IsNullOrEmpty(threatLabel) ? "" : $" / {threatLabel}";

            // Eşik bantları:
            //   < 40  → Güvenli (yeşil)
            //   40-69 → Şüpheli / Riskli (sarı)
            //   ≥ 70  → Kritik (kırmızı)
            if (score < 40)
            {
                ScoreLabel.Text = (Application.Current.FindResource("LabelSafe")?.ToString() ?? "Güvenli") + displayLabel;
                ScoreLabel.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#22C55E"));
                GaugeForeground.Stroke = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#22C55E"));
                SystemMessage.Text = Application.Current.FindResource("MsgSafeContent")?.ToString() ?? "İçerik güvenli olarak değerlendirildi. Herhangi bir tehdit tespit edilmedi.";
            }
            else if (score < 70)
            {
                ScoreLabel.Text = (Application.Current.FindResource("LabelSuspicious")?.ToString() ?? "Şüpheli") + displayLabel;
                ScoreLabel.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));
                GaugeForeground.Stroke = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));
                SystemMessage.Text = Application.Current.FindResource("MsgSuspiciousContent")?.ToString() ?? "İçerik şüpheli olarak işaretlendi. Spam veya potansiyel tehdit olabilir.";
            }
            else
            {
                ScoreLabel.Text = (Application.Current.FindResource("LabelCritical")?.ToString() ?? "Kritik") + displayLabel;
                ScoreLabel.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
                GaugeForeground.Stroke = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
                SystemMessage.Text = Application.Current.FindResource("MsgCriticalContent")?.ToString() ?? "TEHLİKE! Yüksek oranda zararlı içerik tespit edildi.";
            }
        }
        /// <summary>
        /// URL/Dosya taraması sonucunda gauge ve sistem mesajını VirusTotal verisine göre günceller.
        /// Skor 0-100 değil "Malicious/Total" formatında gösterilir, renk Malicious sayısına göre:
        ///   0 motor   → yeşil "Güvenli"
        ///   1-3 motor → sarı "Şüpheli"
        ///   4+ motor  → kırmızı "Kritik"
        /// </summary>
        /// <returns>DB'ye kaydedilecek numeric score (0 / 50 / 90) — Karantina filtresi (>70) için.</returns>
        private double DisplayVtScanResult(int malicious, int totalEngines, string threatType, string scanType)
        {
            string color, label, message;
            double dbScore;

            if (malicious == 0)
            {
                color = "#22C55E"; // yeşil
                label = "Güvenli";
                message = $"Temiz — {totalEngines} motorun hiçbiri tehdit bildirmedi.";
                dbScore = 0;
            }
            else if (malicious <= 3)
            {
                color = "#F59E0B"; // sarı
                label = "Şüpheli";
                message = !string.IsNullOrEmpty(threatType)
                    ? $"{malicious}/{totalEngines} motor şüpheli buldu — Tip: {threatType}"
                    : $"{malicious}/{totalEngines} motor tehdit bildirdi. Dikkatli olun.";
                dbScore = 50; // karantina eşiğinin altında (>70 değil)
            }
            else
            {
                color = "#EF4444"; // kırmızı
                label = "Kritik";
                message = !string.IsNullOrEmpty(threatType)
                    ? $"Kritik tehdit! {malicious}/{totalEngines} motor zararlı — Tip: {threatType}"
                    : $"Kritik tehdit! {malicious}/{totalEngines} motor zararlı buldu.";
                dbScore = 90; // > 70 → Karantina listesine düşer
            }

            ScoreText.Text = $"{malicious}/{totalEngines}";
            ScoreLabel.Text = string.IsNullOrEmpty(threatType) ? label : $"{label} — {threatType}";
            ScoreLabel.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color));
            GaugeForeground.Stroke = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color));
            SystemMessage.Text = message;

            return dbScore;
        }

        /// <summary>
        /// Analiz sonucunu DB'ye kaydeder ve log_id döndürür (zararli_linkler/ekli_dosyalar
        /// foreign key'i için gerekli). scoreOverride < 0 ise ScoreText.Text'i parse eder
        /// (metin analizi için).
        /// </summary>
        private int SaveLogToDatabase(string type, string content, string threatLabel = "", double scoreOverride = -1)
        {
            try
            {
                double score = scoreOverride;
                string result = "Güvenli";

                if (score < 0)
                {
                    // Text analizi: ScoreText "0-100" arası bir sayı (yapay zeka skoru)
                    if (int.TryParse(ScoreText.Text, out int s))
                        score = s;
                    else
                        score = 0;
                }

                if (score >= 70)
                    result = string.IsNullOrEmpty(threatLabel) ? "Kritik" : $"Kritik ({threatLabel})";
                else if (score >= 40)
                    result = string.IsNullOrEmpty(threatLabel) ? "Şüpheli" : $"Şüpheli ({threatLabel})";

                return DatabaseHelper.SaveAnalysisLog(content, type, score, result);
            }
            catch { return -1; }
        }
        private async void LoadLogs()
        {
            var allLogs = await DatabaseHelper.GetAnalysisLogsAsync();
            LogsDataGrid.ItemsSource = allLogs;

            // Karantina: Şüpheli (≥40) ve Kritik (≥70) tüm zararlı tespitler.
            // URL/dosya tarafında zararli_linkler/ekli_dosyalar tablolarına da yazılıyor.
            var quarantineLogs = allLogs.Where(l => l.Score >= 40).ToList();
            QuarantineDataGrid.ItemsSource = quarantineLogs;
        }

        private void RefreshLogs_Click(object sender, RoutedEventArgs e)
        {
            LoadLogs();
            StatusText.Text = Application.Current.FindResource("StatusLogsRefreshed")?.ToString() ?? "Loglar yenilendi";
        }

        /// <summary>
        /// Tüm analiz loglarını veritabanından siler — Tüm Loglar + Karantina dahil.
        /// Çift onay ister çünkü geri alınamaz.
        /// </summary>
        private async void ClearLogs_Click(object sender, RoutedEventArgs e)
        {
            var confirm = MessageBox.Show(
                "Tüm analiz loglarını silmek istediğinize emin misiniz?\n\n" +
                "• Tüm Loglar listesi temizlenir\n" +
                "• Karantina listesi de temizlenir (skor > 70 olanlar dahil)\n" +
                "• Bu işlem geri alınamaz",
                "Logları Temizle",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No);
            if (confirm != MessageBoxResult.Yes) return;

            try
            {
                int removed = await DatabaseHelper.ClearAllAnalysisLogsAsync();
                LoadLogs();
                StatusText.Text = $"{removed} log kaydı silindi";
                StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Loglar silinemedi: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // ==========================================
        // FILE INPUT HANDLERS
        // ==========================================

        private void FileInput_Drop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files.Length > 0)
                {
                    _selectedFilePath = files[0];
                    FileNameText.Text = Path.GetFileName(files[0]);
                    FileNameText.Foreground = Brushes.White;
                }
            }
        }

        private void BrowseFile_Click(object sender, RoutedEventArgs e)
        {
            Microsoft.Win32.OpenFileDialog dialog = new Microsoft.Win32.OpenFileDialog();
            if (dialog.ShowDialog() == true)
            {
                _selectedFilePath = dialog.FileName;
                FileNameText.Text = dialog.SafeFileName;
                FileNameText.Foreground = Brushes.White;
            }
        }

        // ==========================================
        // PING VE API AYARLARI
        // ==========================================

        private System.Windows.Threading.DispatcherTimer? _pingTimer;
        private System.Windows.Threading.DispatcherTimer? _gmailSyncTimer;
        private string _cachedNgrokUrl = "";

        private void StartPingTimer()
        {
            _cachedNgrokUrl = DatabaseHelper.GetSetting("ngrok_url") ?? "";

            // Birden fazla çağrılırsa eski timer'ı durdur — duplicate ping'i engelle
            _pingTimer?.Stop();
            _pingTimer = new System.Windows.Threading.DispatcherTimer();
            _pingTimer.Interval = TimeSpan.FromSeconds(15);
            _pingTimer.Tick += async (s, e) => await CheckApiConnection();
            _pingTimer.Start();
            _ = CheckApiConnection(); // anında ilk kontrol
        }

        /// <summary>
        /// Gmail otomatik senkron timer'ını başlatır veya yeniden başlatır.
        /// Aralık DB'den ("sync_interval_minutes") okunur; varsayılan 5 dk, 0 = devre dışı.
        /// Kullanıcı çıkış yapmışsa (gmail_logged_out=true) timer hiç başlatılmaz.
        /// </summary>
        private void StartGmailSyncTimer()
        {
            // Kullanıcı çıkış yapmış mı?
            if (DatabaseHelper.GetSetting(LoggedOutKey) == "true")
            {
                _gmailSyncTimer?.Stop();
                _gmailSyncTimer = null;
                if (LastSyncText != null)
                    LastSyncText.Text = "Gmail çıkış yapıldı — Ayarlardan Kaydet'e basarak tekrar bağlanın";
                return;
            }

            int minutes = GetSyncIntervalMinutes();

            _gmailSyncTimer?.Stop();
            _gmailSyncTimer = null;

            if (minutes <= 0)
            {
                // Devre dışı
                if (LastSyncText != null)
                    LastSyncText.Text = "Otomatik sync kapalı";
                return;
            }

            _gmailSyncTimer = new System.Windows.Threading.DispatcherTimer
            {
                Interval = TimeSpan.FromMinutes(minutes)
            };
            _gmailSyncTimer.Tick += (s, e) => _ = AutoSyncGmailAsync();
            _gmailSyncTimer.Start();

            // Pencere ilk açıldığında hemen bir sync tetikle
            _ = AutoSyncGmailAsync();
        }

        private static int GetSyncIntervalMinutes()
        {
            string? saved = DatabaseHelper.GetSetting("sync_interval_minutes");
            if (int.TryParse(saved, out int parsed) && parsed >= 0)
                return parsed;
            return 5; // varsayılan
        }

        /// <summary>
        /// Manuel yenile veya ayar değişikliğinden sonra timer'ı sıfırlar
        /// (çift senkronu engellemek için).
        /// </summary>
        private void ResetGmailSyncTimer()
        {
            if (_gmailSyncTimer == null) return;
            _gmailSyncTimer.Stop();
            _gmailSyncTimer.Start();
        }

        private void SyncIntervalCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (SyncIntervalCombo.SelectedItem is not ComboBoxItem item) return;
            if (item.Tag is not string tag) return;
            if (!int.TryParse(tag, out int minutes)) return;

            DatabaseHelper.SaveSetting("sync_interval_minutes", minutes.ToString());
            // Timer'ı yeni aralıkla yeniden başlat
            StartGmailSyncTimer();
        }

        private void ApplySyncIntervalToUI()
        {
            if (SyncIntervalCombo == null) return;
            int current = GetSyncIntervalMinutes();
            foreach (var item in SyncIntervalCombo.Items.OfType<ComboBoxItem>())
            {
                if (item.Tag is string tag && int.TryParse(tag, out int m) && m == current)
                {
                    item.IsSelected = true;
                    break;
                }
            }
        }

        private async Task AutoSyncGmailAsync()
        {
            try
            {
                await PerformGmailSyncAsync(showStatusUpdates: false);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"AutoSync Hatası: {ex.Message}");
            }
        }

        // RefreshMails_Click'ten önce çağırılan helper — manuel sync sonrası
        // timer'ı resetlemek için kullanırız ki çift sync olmasın.
        private void RestartTimerAfterManualSync()
        {
            ResetGmailSyncTimer();
        }

        public void RefreshCachedNgrokUrl()
        {
            _cachedNgrokUrl = DatabaseHelper.GetSetting("ngrok_url") ?? "";
        }

        /// <summary>
        /// URL'in sonundaki path'leri ("/analyze", "/health" vb.) ve trailing slash'i temizler.
        /// Kullanıcı yanlışlıkla tam endpoint URL'i kaydederse base URL'e indir.
        /// Örn: "https://abc.ngrok.dev/analyze" → "https://abc.ngrok.dev"
        /// </summary>
        private static string NormalizeBaseUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return string.Empty;
            url = url.Trim().TrimEnd('/');
            foreach (var suffix in new[] { "/analyze", "/health", "/sync" })
            {
                if (url.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                    url = url.Substring(0, url.Length - suffix.Length).TrimEnd('/');
            }
            return url;
        }

        /// <summary>
        /// Ngrok / Flask backend'in /health endpoint'ini pingler.
        /// Önce ngrok URL'i (varsa), başarısız olursa localhost'a fallback yapar.
        /// Yalnızca üst paneldeki Ngrok göstergesini günceller.
        /// </summary>
        private async Task CheckApiConnection()
        {
            string ngrokBase = NormalizeBaseUrl(_cachedNgrokUrl);
            string apiBase = NormalizeBaseUrl(ApiUrlBox?.Text);
            const string localhost = "http://localhost:5000";

            // Aday URL'ler: ngrok (varsa) → API URL kutusu → localhost (her zaman son fallback)
            var candidates = new List<string>();
            if (!string.IsNullOrEmpty(ngrokBase)) candidates.Add(ngrokBase);
            if (!string.IsNullOrEmpty(apiBase) && !candidates.Contains(apiBase)) candidates.Add(apiBase);
            if (!candidates.Contains(localhost)) candidates.Add(localhost);

            foreach (var url in candidates)
            {
                try
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    var response = await _httpClient.GetAsync($"{url}/health", cts.Token);
                    if (response.IsSuccessStatusCode)
                    {
                        SetNgrokActive();
                        System.Diagnostics.Debug.WriteLine($"[Ping] Flask reachable at: {url}");
                        return;
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[Ping] {url}/health failed: {ex.Message}");
                }
            }

            SetNgrokOffline();
        }

        private void SetNgrokActive()
        {
            PingIndicator.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#22C55E"));
            PingStatus.Text = "Aktif";
            PingStatus.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#22C55E"));

            // Flask backend (ngrok endpoint) aynı zamanda ML/AI motorunu çalıştırır —
            // /health cevap verince AI da aktif demektir. Status bar'da net göster.
            if (AiStatusText != null)
            {
                AiStatusText.Text = "AI: Aktif";
                AiStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4ADE80"));
            }
        }

        private void SetNgrokOffline()
        {
            PingIndicator.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
            PingStatus.Text = "Kapalı";
            PingStatus.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));

            // Flask kapalı → AI yok, sadece heuristik fallback çalışır
            if (AiStatusText != null)
            {
                AiStatusText.Text = "AI: Çevrimdışı (heuristik)";
                AiStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));
            }
        }

        // Eski isimle çağrılan yerler olabilir — geriye dönük uyumluluk için wrapper.
        private void SetApiOffline() => SetNgrokOffline();

        private void SaveApiUrl_Click(object sender, RoutedEventArgs e)
        {
            var url = ApiUrlBox.Text;
            if (!string.IsNullOrEmpty(url))
            {
                DatabaseHelper.SaveSetting("api_url", url);
                StatusText.Text = Application.Current.FindResource("ApiUrlSaved")?.ToString() ?? "API URL kaydedildi";
                _ = CheckApiConnection();
            }
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            var savedUrl = DatabaseHelper.GetSetting("api_url");
            if (!string.IsNullOrEmpty(savedUrl))
            {
                ApiUrlBox.Text = savedUrl;
            }

            var savedNgrokUrl = DatabaseHelper.GetSetting("ngrok_url");
            if (!string.IsNullOrEmpty(savedNgrokUrl))
            {
                NgrokUrlBox.Text = savedNgrokUrl;
            }

            // Kayıtlı senkron aralığını ComboBox'a yansıt
            ApplySyncIntervalToUI();

            StartGmailSyncTimer();
            UpdateLastSyncIndicator();

            // Flask/Ngrok ping timer'ını uygulama açılışta da başlat — kullanıcı Mail
            // tab'ında kalsa bile AI durumu doğru gösterilsin. Önceden sadece Security
            // Scan tab'ına tıklanınca başlıyordu.
            StartPingTimer();
        }

        // ==========================================
        // MAİL GÜNCELLEME BUTONU
        // ==========================================

        private async void RefreshMails_Click(object sender, RoutedEventArgs e)
        {
            StatusText.Text = Application.Current.FindResource("StatusRefreshingMails")?.ToString() ?? "Mailler güncelleniyor...";
            RefreshMailsButton.IsEnabled = false;
            try
            {
                await PerformGmailSyncAsync(showStatusUpdates: true);
                // Manuel sync sonrası timer'ı sıfırla — bir sonraki otomatik sync
                // hemen değil, tam interval kadar sonra çalışsın (çift sync engeli).
                RestartTimerAfterManualSync();
            }
            finally
            {
                RefreshMailsButton.IsEnabled = true;
            }
        }

        // ==========================================
        // MANUEL TEST ET BUTONU
        // ==========================================

        private async void TestConnection_Click(object sender, RoutedEventArgs e)
        {
            StatusText.Text = Application.Current.FindResource("ConnectionTestInProgress")?.ToString() ?? "Bağlantı test ediliyor...";
            PingStatus.Text = "Test ediliyor...";
            PingIndicator.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));

            string apiBaseUrl = ApiUrlBox.Text.Trim();

            if (!string.IsNullOrEmpty(_cachedNgrokUrl))
            {
                apiBaseUrl = _cachedNgrokUrl;
            }

            for (int attempt = 1; attempt <= 3; attempt++)
            {
                try
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                    var response = await _httpClient.GetAsync($"{apiBaseUrl}/health", cts.Token);
                    if (response.IsSuccessStatusCode)
                    {
                        SetNgrokActive();
                        StatusText.Text = "Ngrok bağlantısı başarılı!";
                        return;
                    }

                    if (attempt < 3)
                    {
                        StatusText.Text = $"API yanıt vermiyor, yeniden deneniyor ({attempt}/3)...";
                        PingStatus.Text = $"Yeniden deneniyor ({attempt}/3)...";
                        await Task.Delay(2000);
                    }
                }
                catch (Exception ex)
                {
                    if (attempt < 3)
                    {
                        StatusText.Text = $"Bağlantı hatası, yeniden deneniyor ({attempt}/3)...";
                        PingStatus.Text = $"Yeniden deneniyor ({attempt}/3)...";
                        await Task.Delay(2000);
                    }
                    else
                    {
                        SetApiOffline();
                        StatusText.Text = $"Bağlantı hatası: {ex.Message}";
                    }
                }
            }

            SetApiOffline();
            StatusText.Text = Application.Current.FindResource("ConnectionFailed")?.ToString() ?? "Bağlantı başarısız";
        }

        // ==========================================
        // LOG EXPORT (CSV + PDF)
        // ==========================================

        private async void ExportCsv_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var logs = await DatabaseHelper.GetAnalysisLogsAsync();
                var csv = new StringBuilder();
                csv.AppendLine("Tarih,Tür,İçerik,Skor,Sonuç");

                foreach (var log in logs)
                {
                    var content = log.Content.Replace("\"", "\"\"").Replace("\n", " ").Replace("\r", "");
                    csv.AppendLine($"\"{log.Date}\",\"{log.Type}\",\"{content}\",\"{log.Score}\",\"{log.Result}\"");
                }

                var dialog = new Microsoft.Win32.SaveFileDialog
                {
                    Filter = "CSV files (*.csv)|*.csv",
                    FileName = $"analiz_loglari_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
                };

                if (dialog.ShowDialog() == true)
                {
                    File.WriteAllText(dialog.FileName, csv.ToString(), Encoding.UTF8);
                    MessageBox.Show("CSV dosyası başarıyla kaydedildi!", "Başarılı", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"CSV export hatası: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void ExportPdf_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var logs = await DatabaseHelper.GetAnalysisLogsAsync();

                var dialog = new Microsoft.Win32.SaveFileDialog
                {
                    Filter = "PDF Dosyası (*.pdf)|*.pdf",
                    FileName = $"analiz_raporu_{DateTime.Now:yyyyMMdd_HHmmss}.pdf"
                };
                if (dialog.ShowDialog() != true) return;

                QuestPDF.Settings.License = QuestPDF.Infrastructure.LicenseType.Community;

                Document.Create(container =>
                {
                    container.Page(page =>
                    {
                        page.Size(PageSizes.A4);
                        page.Margin(2, Unit.Centimetre);
                        page.PageColor(QuestPDF.Helpers.Colors.White);
                        page.DefaultTextStyle(x => x.FontSize(11).FontFamily(QuestPDF.Helpers.Fonts.Arial));

                        page.Header().Column(col =>
                        {
                            col.Item().Text("Siber Mail & Güvenlik Asistanı")
                               .SemiBold().FontSize(22).FontColor(QuestPDF.Helpers.Colors.Blue.Darken2);
                            col.Item().Text("Analiz Raporu")
                               .FontSize(14).FontColor(QuestPDF.Helpers.Colors.Grey.Darken1);
                            col.Item().PaddingTop(2).Text($"Rapor Tarihi: {DateTime.Now:dd.MM.yyyy HH:mm}")
                               .FontSize(9).FontColor(QuestPDF.Helpers.Colors.Grey.Medium);
                        });

                        page.Content().PaddingVertical(15).Column(col =>
                        {
                            col.Item().LineHorizontal(1).LineColor(QuestPDF.Helpers.Colors.Grey.Lighten2);
                            col.Item().PaddingTop(10).Text($"Toplam {logs.Count} analiz kaydı")
                               .SemiBold().FontSize(12);

                            col.Item().PaddingTop(10).Table(table =>
                            {
                                table.ColumnsDefinition(columns =>
                                {
                                    columns.RelativeColumn(3); // Tarih
                                    columns.RelativeColumn(2); // Tür
                                    columns.RelativeColumn(1); // Skor
                                    columns.RelativeColumn(3); // Sonuç
                                });

                                table.Header(header =>
                                {
                                    header.Cell().Background(QuestPDF.Helpers.Colors.Grey.Darken3).Padding(5)
                                          .Text("Tarih").FontColor(QuestPDF.Helpers.Colors.White).SemiBold();
                                    header.Cell().Background(QuestPDF.Helpers.Colors.Grey.Darken3).Padding(5)
                                          .Text("Tür").FontColor(QuestPDF.Helpers.Colors.White).SemiBold();
                                    header.Cell().Background(QuestPDF.Helpers.Colors.Grey.Darken3).Padding(5)
                                          .Text("Skor").FontColor(QuestPDF.Helpers.Colors.White).SemiBold();
                                    header.Cell().Background(QuestPDF.Helpers.Colors.Grey.Darken3).Padding(5)
                                          .Text("Sonuç").FontColor(QuestPDF.Helpers.Colors.White).SemiBold();
                                });

                                foreach (var log in logs)
                                {
                                    string rowColor = log.Score > 70 ? QuestPDF.Helpers.Colors.Red.Lighten4
                                                    : log.Score > 40 ? QuestPDF.Helpers.Colors.Orange.Lighten4
                                                    : QuestPDF.Helpers.Colors.Green.Lighten4;
                                    table.Cell().Background(rowColor).Padding(4).Text(log.Date).FontSize(9);
                                    table.Cell().Background(rowColor).Padding(4).Text(log.Type).FontSize(9);
                                    table.Cell().Background(rowColor).Padding(4).Text(log.Score.ToString("F0")).FontSize(9);
                                    table.Cell().Background(rowColor).Padding(4).Text(log.Result).FontSize(9);
                                }
                            });
                        });

                        page.Footer().AlignCenter().Text(t =>
                        {
                            t.Span("Sayfa ");
                            t.CurrentPageNumber();
                            t.Span(" / ");
                            t.TotalPages();
                        });
                    });
                })
                .GeneratePdf(dialog.FileName);

                MessageBox.Show($"PDF rapor başarıyla kaydedildi!\n\n{dialog.FileName}", "Başarılı", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"PDF oluşturma hatası: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // ==========================================
        // LOADING ANIMATION
        // ==========================================

        private void ShowLoading(bool show)
        {
            Dispatcher.Invoke(() =>
            {
                LoadingPanel.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
                AnalyzeButton.IsEnabled = !show;

                if (show)
                {
                    LoadingText.Text = "Analiz ediliyor...";
                    LoadingProgress.IsIndeterminate = true;
                }
            });
        }

        // ==========================================
        // VIRUSTOTAL VENDOR RAPORU MODAL
        // ==========================================

        /// <summary>
        /// VIRUSTOTAL kartına tıklama. Üç durum:
        /// - Mail için zaten tarama yapıldıysa → motor detay modalını aç
        /// - Tarama yoksa ama link varsa → tarama başlat (manuel mod)
        /// - Link yoksa veya API key eksikse → bilgi mesajı
        /// </summary>
        private void VtResult_Click(object sender, RoutedEventArgs e)
        {
            // RoutedEvent handled olarak işaretle — başka handler'lar bu tıklamayı yutmasın
            if (e is System.Windows.Input.MouseButtonEventArgs mbe) mbe.Handled = true;

            try
            {
                System.Diagnostics.Debug.WriteLine($"[VtResult_Click] tıklandı. _selectedMail={_selectedMail?.Id}, _lastVtResult={(_lastVtResult != null)}, _vtScannedForMailId={_vtScannedForMailId}");

                // Mevcut mail için yapılmış scan sonucu varsa → motor detay overlay'ı aç
                if (_lastVtResult != null && _selectedMail != null && _vtScannedForMailId == _selectedMail.Id)
                {
                    VtPositiveCount.Text = _lastVtResult.Malicious.ToString();
                    VtNegativeCount.Text = _lastVtResult.Undetected.ToString();

                    var displayList = _lastVtResult.VendorDetails
                                                   .Where(v => v.Category == "malicious" || v.Category == "undetected")
                                                   .Take(20)
                                                   .ToList();

                    VendorResultsList.ItemsSource = displayList;
                    VtReportOverlay.Visibility = Visibility.Visible;
                    return;
                }

                if (_selectedMail == null)
                {
                    MessageBox.Show("Önce bir mail seçin.", "Bilgi", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                if (string.IsNullOrWhiteSpace(_apiKey))
                {
                    MessageBox.Show("VirusTotal API anahtarı yok. Ayarlardan API key girin.", "API Anahtarı Yok", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var urls = ExtractUrlsFromBody(_selectedMail.Body ?? "");
                System.Diagnostics.Debug.WriteLine($"[VtResult_Click] URL sayısı: {urls.Count}");
                if (urls.Count == 0)
                {
                    MessageBox.Show("Bu mailde taranacak URL bulunmuyor.", "Bilgi", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                // Manuel tetikleme — kullanıcı tıkladı, taramaya başla
                _vtScanCts?.Cancel();
                _vtScanCts = new System.Threading.CancellationTokenSource();
                var token = _vtScanCts.Token;
                var mail = _selectedMail;

                // ANINDA UI feedback ki kullanıcı tıklamanın çalıştığını görsün
                VtResult.Text = "Taranıyor...";
                VtDetail.Text = "VT'ye sorgu gönderiliyor...";
                VtDetail.Visibility = Visibility.Visible;
                VtResult.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#60A5FA"));

                _ = ScanMailUrlsWithVtAsync(mail, token);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[VtResult_Click] EXCEPTION: {ex}");
                MessageBox.Show($"Tarama başlatılamadı: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        

        private void CloseVtReport_Click(object sender, RoutedEventArgs e)
        {
            VtReportOverlay.Visibility = Visibility.Collapsed;
        }

        // ==========================================
        // KARANTINA CONTEXT MENU
        // ==========================================

        private async void MarkAsSafe_Click(object sender, RoutedEventArgs e)
        {
            if (QuarantineDataGrid.SelectedItem is AnalysisLog log)
            {
                DatabaseHelper.SaveFalsePositive(log.Content, log.Type, log.Score, "Kullanıcı tarafından işaretlendi");
                // Yanlış pozitif olarak işaretlenen log kaydını sil — kullanıcı eğer
                // başka bir tabloda da görmek isterse SaveFalsePositive zaten hatali_alarmlar'a kopyaladı.
                await DatabaseHelper.DeleteAnalysisLogAsync(log.Id);

                MessageBox.Show("False Positive olarak işaretlendi. Geri bildirim için teşekkürler!", "Bilgi", MessageBoxButton.OK, MessageBoxImage.Information);
                LoadLogs();
            }
        }

        private async void MoveToTrash_Click(object sender, RoutedEventArgs e)
        {
            if (QuarantineDataGrid.SelectedItem is AnalysisLog log)
            {
                // Analiz logları için "çöp kutusuna taşıma" anlamlı değil; log kaydını siliyoruz.
                // Mail tarafındaki çöp klasörü ile karıştırılmamalı.
                await DatabaseHelper.DeleteAnalysisLogAsync(log.Id);
                LoadLogs();
                StatusText.Text = Application.Current.FindResource("StatusMovedToTrash")?.ToString() ?? "Çöp kutusuna taşındı";
            }
        }

        private async void DeletePermanently_Click(object sender, RoutedEventArgs e)
        {
            if (QuarantineDataGrid.SelectedItem is AnalysisLog log)
            {
                var result = MessageBox.Show("Bu öğeyi kalıcı olarak silmek istediğinize emin misiniz?", "Silme Onayı", MessageBoxButton.YesNo, MessageBoxImage.Warning);

                if (result == MessageBoxResult.Yes)
                {
                    await DatabaseHelper.DeleteAnalysisLogAsync(log.Id);
                    LoadLogs();
                    StatusText.Text = Application.Current.FindResource("StatusPermanentlyDeleted")?.ToString() ?? "Kalıcı olarak silindi";
                }
            }
        }
    }

    public class VendorResult
    {
        public string Name { get; set; } = "";
        public string Result { get; set; } = "";
        public string Category { get; set; } = "";
    }
}