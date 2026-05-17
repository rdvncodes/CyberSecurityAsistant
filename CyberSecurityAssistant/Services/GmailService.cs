using MailKit;
using MailKit.Net.Imap;
using MailKit.Net.Smtp;
using MimeKit;
using System.Text.RegularExpressions;
using System.Web;

namespace CyberSecurityAssistant.Services
{
    public class GmailService : IDisposable
    {
        private ImapClient? _imapClient;
        private string _email = "";
        private string _appPassword = "";

        // Eş zamanlı ConnectAsync çağrılarını sıraya sokar — aynı anda
        // iki yerden bağlanma denemesi olursa biri diğerinin client'ını dispose
        // ediyordu ve ObjectDisposedException fırlatıyordu (startup'taki "hata mesajı").
        private readonly SemaphoreSlim _connectLock = new SemaphoreSlim(1, 1);

        public event EventHandler<string>? StatusChanged;
        public event EventHandler<int>? MailSynced;

        public bool IsConnected => _imapClient?.IsConnected == true && _imapClient?.IsAuthenticated == true;

        public async Task<bool> RetryConnectAsync(string email, string appPassword, int maxRetries = 2)
        {
            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                System.Diagnostics.Debug.WriteLine($"[GmailService] Connection attempt {attempt}/{maxRetries}");
                StatusChanged?.Invoke(this, $"Bağlantı deneniyor... ({attempt}/{maxRetries})");

                bool success = await ConnectAsync(email, appPassword);
                if (success) return true;

                if (attempt < maxRetries)
                {
                    System.Diagnostics.Debug.WriteLine($"[GmailService] Attempt {attempt} failed, waiting 3 seconds before retry...");
                    StatusChanged?.Invoke(this, $"Bağlantı başarısız, {3 * attempt} saniye bekleniyor...");
                    await Task.Delay(3000 * attempt);
                }
            }

            StatusChanged?.Invoke(this, "Gmail bağlantısı başarısız oldu. Lütfen Ayarlar'ı kontrol edin.");
            return false;
        }

        public async Task<bool> ConnectAsync(string email, string appPassword)
        {
            // Eş zamanlı çağrıları sıraya sok — startup'taki yarış koşulunu engeller.
            await _connectLock.WaitAsync();
            try
            {
                // Fast path: zaten bağlı ve auth'lı bir client varsa yeniden bağlanma.
                if (_imapClient != null && _imapClient.IsConnected && _imapClient.IsAuthenticated)
                {
                    System.Diagnostics.Debug.WriteLine("[GmailService] Already connected and authenticated, reusing.");
                    return true;
                }

                _email = email.Trim();
                _appPassword = appPassword.Trim().Replace(" ", "");

                System.Diagnostics.Debug.WriteLine($"[GmailService] Attempting to connect to {email}");

                // Önceki client temiz şekilde kapat (varsa)
                if (_imapClient != null)
                {
                    try
                    {
                        if (_imapClient.IsConnected)
                            await _imapClient.DisconnectAsync(true);
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[GmailService] Disconnect existing client failed (non-fatal): {ex.Message}");
                    }
                    _imapClient.Dispose();
                    _imapClient = null;
                }

                _imapClient = new ImapClient();
                _imapClient.CheckCertificateRevocation = false;
                _imapClient.Timeout = 30000;

                System.Diagnostics.Debug.WriteLine("[GmailService] Connecting to imap.gmail.com:993...");
                await _imapClient.ConnectAsync("imap.gmail.com", 993, true);

                _imapClient.AuthenticationMechanisms.Remove("XOAUTH2");

                System.Diagnostics.Debug.WriteLine($"[GmailService] Authenticating with email: {_email}");
                await _imapClient.AuthenticateAsync(_email, _appPassword);
                System.Diagnostics.Debug.WriteLine("[GmailService] Authentication successful!");

                StatusChanged?.Invoke(this, "IMAP Bağlantı başarılı");
                return true;
            }
            catch (MailKit.Security.AuthenticationException authEx)
            {
                // Bu kritik bir hata — kullanıcının App Password'unu güncellemesi gerek.
                // MessageBox burada uygun (kullanıcı eylem almalı).
                string errorMsg = $"Kimlik doğrulama hatası!\n\nOlası Sebepler:\n• App Password yanlış veya süresi dolmuş\n• 2FA (2 Adımlı Doğrulama) kapalı olabilir\n• Gmail hesabında 'Less secure app access' yerine App Password kullanılmalı\n\nHata: {authEx.Message}";
                System.Windows.MessageBox.Show(errorMsg, "Gmail Bağlantı Hatası", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
                StatusChanged?.Invoke(this, "IMAP Hatası: Kimlik doğrulama başarısız");
                System.Diagnostics.Debug.WriteLine($"[GmailService] Auth Error: {authEx}");
                return false;
            }
            catch (ObjectDisposedException ex)
            {
                // Yarış koşulu / paralel dispose — sessizce log'la, sonraki deneme başarılı olur.
                System.Diagnostics.Debug.WriteLine($"[GmailService] ObjectDisposed (race; retry will succeed): {ex.Message}");
                StatusChanged?.Invoke(this, "IMAP yeniden başlatılıyor...");
                return false;
            }
            catch (MailKit.Net.Imap.ImapCommandException imapEx)
            {
                // Geçici IMAP hatası — popup yerine sessizce log + status bar mesajı yeterli.
                // Auto-sync birkaç dakika sonra yine deneyecek.
                StatusChanged?.Invoke(this, $"IMAP Hatası: {imapEx.Message}");
                System.Diagnostics.Debug.WriteLine($"[GmailService] IMAP Error: {imapEx}");
                return false;
            }
            catch (Exception ex)
            {
                // Genel hatalar (ağ kopukluğu, timeout vb.) — popup ile rahatsız etme,
                // status bar'da göster, bir sonraki sync denemesi otomatik kurtarır.
                StatusChanged?.Invoke(this, $"Gmail bağlantı sorunu: {ex.Message}");
                System.Diagnostics.Debug.WriteLine($"[GmailService] Full Error: {ex}");
                return false;
            }
            finally
            {
                _connectLock.Release();
            }
        }

        public async Task DisconnectAsync()
        {
            if (_imapClient?.IsConnected == true)
            {
                await _imapClient.DisconnectAsync(true);
            }
        }

        private static string ExtractBodyText(MimeMessage message)
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(message.TextBody))
                    return message.TextBody;

                if (!string.IsNullOrWhiteSpace(message.HtmlBody))
                {
                    string html = message.HtmlBody;

                    html = Regex.Replace(html, @"<script[^>]*>[\s\S]*?</script>", "", RegexOptions.IgnoreCase);
                    html = Regex.Replace(html, @"<style[^>]*>[\s\S]*?</style>", "", RegexOptions.IgnoreCase);
                    html = Regex.Replace(html, @"<[^>]+>", " ");
                    html = Regex.Replace(html, @"\s+", " ");
                    html = HttpUtility.HtmlDecode(html);
                    html = html.Trim();

                    if (html.Length > 50)
                        return html;
                }

                if (message.Body != null)
                {
                    if (message.Body is TextPart textPart)
                        return textPart.Text;

                    if (message.Body is Multipart multipart)
                    {
                        var plainPart = multipart.FirstOrDefault(p => p is TextPart tp && tp.IsPlain);
                        if (plainPart is TextPart plainText)
                            return plainText.Text;

                        var htmlPart = multipart.FirstOrDefault(p => p is TextPart tp && tp.IsHtml);
                        if (htmlPart is TextPart htmlText)
                        {
                            string html = htmlText.Text;
                            html = Regex.Replace(html, @"<[^>]+>", " ");
                            html = Regex.Replace(html, @"\s+", " ");
                            html = HttpUtility.HtmlDecode(html);
                            return html.Trim();
                        }
                    }
                }

                return "";
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"ExtractBodyText Error: {ex.Message}");
                return "";
            }
        }

        public async Task<List<SyncedMail>> SyncInboxAsync(int limit = 50)
        {
            var syncedMails = new List<SyncedMail>();

            try
            {
                if (_imapClient == null)
                {
                    StatusChanged?.Invoke(this, "IMAP client yok, önce bağlanın");
                    System.Diagnostics.Debug.WriteLine("[GmailService] SyncInboxAsync: _imapClient is null");
                    return syncedMails;
                }

                if (!_imapClient.IsConnected)
                {
                    StatusChanged?.Invoke(this, "IMAP bağlantısı yok, tekrar bağlanılıyor...");
                    System.Diagnostics.Debug.WriteLine("[GmailService] SyncInboxAsync: Not connected, attempting reconnect...");
                    return syncedMails;
                }

                System.Diagnostics.Debug.WriteLine($"[GmailService] SyncInboxAsync: Opening inbox...");
                var inbox = _imapClient.Inbox;
                await inbox.OpenAsync(FolderAccess.ReadWrite);

                var totalCount = inbox.Count;
                var startIndex = Math.Max(0, totalCount - limit);
                System.Diagnostics.Debug.WriteLine($"[GmailService] Total emails: {totalCount}, syncing last {limit}");

                for (int i = totalCount - 1; i >= startIndex; i--)
                {
                    try
                    {
                        var message = await inbox.GetMessageAsync(i);
                        var bodyText = ExtractBodyText(message);

                        syncedMails.Add(new SyncedMail
                        {
                            MessageId = message.MessageId,
                            Subject = message.Subject ?? "",
                            FromEmail = message.From.Mailboxes.FirstOrDefault()?.Address ?? "",
                            FromName = message.From.Mailboxes.FirstOrDefault()?.Name ?? "",
                            ToEmail = message.To.Mailboxes.FirstOrDefault()?.Address ?? "",
                            Body = bodyText,
                            // .DateTime timezone bilgisini düşürür (Unspecified Kind) — UTC mailler
                            // yerel saate çevrilmeden gösterilir. LocalDateTime DateTimeOffset'i
                            // sistem timezone'una çevirip Kind=Local olarak döndürür.
                            Date = message.Date.LocalDateTime,
                            HasAttachments = message.Attachments.Count() > 0
                        });

                        MailSynced?.Invoke(this, syncedMails.Count);
                    }
                    catch (Exception msgEx)
                    {
                        System.Diagnostics.Debug.WriteLine($"[GmailService] Error fetching message {i}: {msgEx.Message}");
                    }
                }

                await inbox.CloseAsync(false);
                StatusChanged?.Invoke(this, $"{syncedMails.Count} mail senkronize edildi");
                System.Diagnostics.Debug.WriteLine($"[GmailService] Sync completed: {syncedMails.Count} emails");
            }
            catch (MailKit.FolderNotOpenException fEx)
            {
                // Race condition — başka bir sync inbox'ı kapattı.
                // Bu noktada bir kısım mail çekilmiş olabilir, onları döndür.
                System.Diagnostics.Debug.WriteLine($"[GmailService] FolderNotOpen race: {fEx.Message} (so far: {syncedMails.Count} mails)");
                StatusChanged?.Invoke(this, $"Senkron yarı kesildi (paralel erişim) — {syncedMails.Count} mail geldi");
            }
            catch (Exception ex)
            {
                // Hata tipini de logla — "The folde..." kısaltmasını uzat
                System.Diagnostics.Debug.WriteLine($"[GmailService] SyncInboxAsync Error: {ex}");
                StatusChanged?.Invoke(this, $"Senkron hatası ({ex.GetType().Name}): {ex.Message}");
            }

            return syncedMails;
        }

        public async Task<List<SyncedMail>> SyncSentAsync(int limit = 50)
        {
            var syncedMails = new List<SyncedMail>();

            try
            {
                if (_imapClient == null || !_imapClient.IsConnected)
                    return syncedMails;

                var sentFolder = _imapClient.GetFolder("[Gönderilmiş Postalar]");
                if (sentFolder == null)
                    sentFolder = _imapClient.GetFolder("[Sent Mail]");

                if (sentFolder == null)
                {
                    StatusChanged?.Invoke(this, "Giden kutusu bulunamadı");
                    return syncedMails;
                }

                await sentFolder.OpenAsync(FolderAccess.ReadOnly);

                var totalCount = sentFolder.Count;
                var startIndex = Math.Max(0, totalCount - limit);

                for (int i = totalCount - 1; i >= startIndex; i--)
                {
                    var message = await sentFolder.GetMessageAsync(i);

                    var bodyText = ExtractBodyText(message);

                    syncedMails.Add(new SyncedMail
                    {
                        MessageId = message.MessageId,
                        Subject = message.Subject ?? "",
                        FromEmail = message.From.Mailboxes.FirstOrDefault()?.Address ?? "",
                        FromName = message.From.Mailboxes.FirstOrDefault()?.Name ?? "",
                        ToEmail = message.To.Mailboxes.FirstOrDefault()?.Address ?? "",
                        Body = bodyText,
                        Date = message.Date.DateTime,
                        HasAttachments = message.Attachments.Count() > 0
                    });
                }

                await sentFolder.CloseAsync(false);
                StatusChanged?.Invoke(this, $"{syncedMails.Count} giden mail senkronize edildi");
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke(this, $"Giden kutusu hatası: {ex.Message}");
            }

            return syncedMails;
        }

        /// <summary>
        /// Mail gönderir. attachmentPaths verilirse MimeKit BodyBuilder ile ekler dahil edilir.
        /// Boş veya null liste → düz metin/HTML body.
        /// </summary>
        public async Task<bool> SendEmailAsync(string toEmail, string subject, string body, bool isHtml = false, IEnumerable<string>? attachmentPaths = null)
        {
            try
            {
                using var smtpClient = new SmtpClient();
                smtpClient.CheckCertificateRevocation = false;

                await smtpClient.ConnectAsync("smtp.gmail.com", 587, false);
                await smtpClient.AuthenticateAsync(_email, _appPassword);

                var message = new MimeMessage();
                message.From.Add(new MailboxAddress(_email, _email));
                message.To.Add(new MailboxAddress(toEmail, toEmail));
                message.Subject = subject;

                // Ekler varsa BodyBuilder kullan; yoksa eski sade TextPart yolu
                bool hasAttachments = attachmentPaths != null && attachmentPaths.Any();
                if (hasAttachments)
                {
                    var builder = new BodyBuilder();
                    if (isHtml) builder.HtmlBody = body;
                    else        builder.TextBody = body;

                    foreach (var path in attachmentPaths!)
                    {
                        if (!string.IsNullOrWhiteSpace(path) && System.IO.File.Exists(path))
                        {
                            try { await builder.Attachments.AddAsync(path); }
                            catch (Exception ex)
                            {
                                System.Diagnostics.Debug.WriteLine($"[GmailService] Ek eklenemedi {path}: {ex.Message}");
                            }
                        }
                    }
                    message.Body = builder.ToMessageBody();
                }
                else
                {
                    if (isHtml) message.Body = new TextPart("html") { Text = body };
                    else        message.Body = new TextPart("plain") { Text = body };
                }

                await smtpClient.SendAsync(message);
                await smtpClient.DisconnectAsync(true);

                int attachCount = hasAttachments ? attachmentPaths!.Count() : 0;
                StatusChanged?.Invoke(this, attachCount > 0 ? $"Mail gönderildi ({attachCount} ek dahil)" : "Mail gönderildi");
                return true;
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke(this, $"Gönderim hatası: {ex.Message}");
                return false;
            }
        }

        public async Task MarkAsReadAsync(string messageId)
        {
            try
            {
                if (_imapClient == null || !_imapClient.IsConnected)
                    return;

                var inbox = _imapClient.Inbox;
                await inbox.OpenAsync(FolderAccess.ReadWrite);

                for (int i = 0; i < inbox.Count; i++)
                {
                    var message = await inbox.GetMessageAsync(i);
                    if (message.MessageId == messageId)
                    {
                        await inbox.SetFlagsAsync(i, MessageFlags.Seen, true);
                        break;
                    }
                }

                await inbox.CloseAsync(false);
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke(this, $"Okundu işaretleme hatası: {ex.Message}");
            }
        }

        
        public async Task MoveToTrashAsync(string messageId)
        {
            // SpecialFolder.Trash önce denenir — Gmail sunucusu IMAP capability'leri üzerinden
            // gerçek Trash klasörünü bildirir. Fallback olarak bilinen klasör adları denenir
            // (farklı Gmail dil ayarları için).
            await MoveToFolderAsync(messageId,
                SpecialFolder.Trash,
                new[] { "[Gmail]/Trash", "[Gmail]/Bin", "[Gmail]/Çöp Kutusu", "[Trash]", "Trash", "Çöp Kutusu" },
                "çöp kutusu");
        }

        public async Task<bool> DeleteFromGmailAsync(string messageId)
        {
            try
            {
                if (_imapClient == null || !_imapClient.IsConnected)
                    return false;

                var inbox = _imapClient.Inbox;
                await inbox.OpenAsync(FolderAccess.ReadWrite);

                bool deleted = false;
                for (int i = 0; i < inbox.Count; i++)
                {
                    var message = await inbox.GetMessageAsync(i);
                    if (message.MessageId == messageId)
                    {
                        await inbox.AddFlagsAsync(i, MessageFlags.Deleted, true);
                        await inbox.ExpungeAsync();
                        deleted = true;
                        break;
                    }
                }

                await inbox.CloseAsync(false);
                if (deleted)
                    StatusChanged?.Invoke(this, "Tehdit içeren mail Gmail'den silindi");
                return deleted;
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke(this, $"Mail silme hatası: {ex.Message}");
                return false;
            }
        }

        private async Task MoveToFolderAsync(string messageId, SpecialFolder specialFolder, string[] candidateFolders, string label)
        {
            try
            {
                if (_imapClient == null || !_imapClient.IsConnected || string.IsNullOrEmpty(messageId))
                    return;

                // 1) SpecialFolder API'sini dene — sunucu IMAP capability'lerinden bildirir.
                IMailFolder? targetFolder = null;
                try
                {
                    targetFolder = _imapClient.GetFolder(specialFolder);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[GmailService] SpecialFolder.{specialFolder} bulunamadı: {ex.Message}");
                }

                // 2) Fallback: hardcoded klasör isim adayları (Gmail dil ayarına göre)
                if (targetFolder == null)
                {
                    foreach (var name in candidateFolders)
                    {
                        try
                        {
                            targetFolder = _imapClient.GetFolder(name);
                            if (targetFolder != null) break;
                        }
                        catch { /* try next name */ }
                    }
                }

                if (targetFolder == null)
                {
                    StatusChanged?.Invoke(this, $"{label} klasörü bulunamadı");
                    System.Diagnostics.Debug.WriteLine($"[GmailService] {label} klasörü hiçbir adayla bulunamadı.");
                    return;
                }

                var inbox = _imapClient.Inbox;
                await inbox.OpenAsync(FolderAccess.ReadWrite);

                bool moved = false;
                for (int i = 0; i < inbox.Count; i++)
                {
                    var message = await inbox.GetMessageAsync(i);
                    if (message.MessageId == messageId)
                    {
                        await inbox.MoveToAsync(i, targetFolder);
                        moved = true;
                        break;
                    }
                }

                await inbox.CloseAsync(false);

                if (moved)
                    StatusChanged?.Invoke(this, $"Mail {label} olarak işaretlendi");
                else
                    System.Diagnostics.Debug.WriteLine($"[GmailService] MessageId={messageId} inbox'ta bulunamadı (zaten taşınmış olabilir).");
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke(this, $"{label} taşıma hatası: {ex.Message}");
                System.Diagnostics.Debug.WriteLine($"[GmailService] MoveToFolderAsync hatası: {ex}");
            }
        }
        /// <summary>
        /// Trash veya Spam'deki bir maili Gmail Inbox'a geri taşır.
        /// Önce Trash sonra Spam klasörlerinde messageId arayıp Inbox'a MoveToAsync yapar.
        /// </summary>
        public async Task<bool> RestoreToInboxAsync(string messageId)
        {
            try
            {
                if (_imapClient == null || !_imapClient.IsConnected || string.IsNullOrEmpty(messageId))
                    return false;

                var inbox = _imapClient.Inbox;

                // Trash ve Spam'i taramak için aday klasör listesi
                var sourceCandidates = new List<IMailFolder>();
                foreach (var sf in new[] { SpecialFolder.Trash, SpecialFolder.Junk })
                {
                    try
                    {
                        var f = _imapClient.GetFolder(sf);
                        if (f != null) sourceCandidates.Add(f);
                    }
                    catch { }
                }
                foreach (var name in new[] { "[Gmail]/Trash", "[Gmail]/Bin", "[Gmail]/Çöp Kutusu", "[Gmail]/Spam", "[Gmail]/Gereksiz" })
                {
                    try
                    {
                        var f = _imapClient.GetFolder(name);
                        if (f != null && !sourceCandidates.Contains(f)) sourceCandidates.Add(f);
                    }
                    catch { }
                }

                foreach (var source in sourceCandidates)
                {
                    try
                    {
                        await source.OpenAsync(FolderAccess.ReadWrite);
                        bool found = false;
                        for (int i = 0; i < source.Count; i++)
                        {
                            var message = await source.GetMessageAsync(i);
                            if (message.MessageId == messageId)
                            {
                                await source.MoveToAsync(i, inbox);
                                found = true;
                                break;
                            }
                        }
                        await source.CloseAsync(false);
                        if (found)
                        {
                            StatusChanged?.Invoke(this, "Mail Gelen Kutusuna geri taşındı");
                            return true;
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[GmailService] RestoreToInbox - {source.FullName} taramasında hata: {ex.Message}");
                    }
                }

                StatusChanged?.Invoke(this, "Mail kaynak klasörde bulunamadı");
                return false;
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke(this, $"Geri alma hatası: {ex.Message}");
                System.Diagnostics.Debug.WriteLine($"[GmailService] RestoreToInbox hatası: {ex}");
                return false;
            }
        }

        public async Task MoveToSpamAsync(string messageId)
        {
            // SpecialFolder.Junk öncelikli, fallback olarak isim adayları
            await MoveToFolderAsync(messageId,
                SpecialFolder.Junk,
                new[] { "[Gmail]/Spam", "Spam", "[Gmail]/Gereksiz", "Gereksiz", "Junk", "Spamlar" },
                "spam");
        }

        public void Dispose()
        {
            _imapClient?.Dispose();
            _connectLock?.Dispose();
        }
    }

    public class SyncedMail
    {
        public string MessageId { get; set; } = "";
        public string Subject { get; set; } = "";
        public string FromEmail { get; set; } = "";
        public string FromName { get; set; } = "";
        public string ToEmail { get; set; } = "";
        public string Body { get; set; } = "";
        public DateTime Date { get; set; }
        public bool HasAttachments { get; set; }
    }
}