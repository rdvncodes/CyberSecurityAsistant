using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace CyberSecurityAssistant.Services
{
    public class ThreatAnalysisResult
    {
        public double PhishingScore { get; set; }
        public double SpamScore { get; set; }
        public double SqlInjectionScore { get; set; }
        public double XssScore { get; set; }
        public double TrojanScore { get; set; }

        // Eşik bantları (kullanıcı seçimi):
        //   0-39  → Güvenli (yeşil)
        //   40-69 → Şüpheli / Riskli (sarı)       — uyarı gösterilir, taşıma yapılmaz
        //   70+   → Kritik (kırmızı)               — phishing/tehdit → Çöp Kutusu
        // Spam ayrı yönetilir: ≥ 50 → Spam klasörüne taşı
        public bool IsPhishing => PhishingScore >= 70;
        public bool IsSpam => SpamScore >= 50;
        public bool HasSqlInjection => SqlInjectionScore >= 70;
        public bool HasXss => XssScore >= 70;
        public bool HasTrojan => TrojanScore >= 70;

        // 40-69 arası "şüpheli" bandı — UI'da sarı gösterim için
        public bool IsSuspicious =>
            (PhishingScore >= 40 && PhishingScore < 70) ||
            (SqlInjectionScore >= 40 && SqlInjectionScore < 70) ||
            (XssScore >= 40 && XssScore < 70) ||
            (TrojanScore >= 40 && TrojanScore < 70);

        // True for any "dangerous" threat that should result in deletion
        public bool IsDangerous => IsPhishing || HasSqlInjection || HasXss || HasTrojan;

        public string HighestThreatLabel()
        {
            var threats = new (string Name, double Score)[]
            {
                ("Phishing", PhishingScore),
                ("SQL Injection", SqlInjectionScore),
                ("XSS", XssScore),
                ("Trojan", TrojanScore),
                ("Spam", SpamScore)
            };
            var top = threats.OrderByDescending(t => t.Score).First();
            return top.Score >= 40 ? top.Name : "Temiz";
        }
    }

    public class MLModelService
    {
        private readonly string _modelsPath;
        private readonly HttpClient _httpClient;
        private const string DefaultApiUrl = "http://localhost:5000";
        private const int MaxRetries = 2;
        private const int RetryDelayMs = 1000;

        private string _cachedNgrokUrl = "";

        public event EventHandler<string>? StatusChanged;

        public MLModelService()
        {
            _modelsPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Models");
            _httpClient = new HttpClient();
            _httpClient.Timeout = TimeSpan.FromSeconds(5);
            // Token appsettings.json'dan okunur — hardcoded değil
            _httpClient.DefaultRequestHeaders.Add("x-api-key", AppConfig.Settings.InternalApiAuthToken);
            _httpClient.DefaultRequestHeaders.Add("ngrok-skip-browser-warning", "true");

            RefreshCachedUrl();

            if (!Directory.Exists(_modelsPath))
            {
                Directory.CreateDirectory(_modelsPath);
                StatusChanged?.Invoke(this, "Models klasörü oluşturuldu. Lütfen model dosyalarını buraya kopyalayın.");
            }
        }

        public void RefreshCachedUrl()
        {
            _cachedNgrokUrl = DatabaseHelper.GetSetting("ngrok_url") ?? "";
        }

        /// <summary>
        /// URL'i normalize eder — kullanıcı yanlışlıkla "/analyze" eklemiş olabilir,
        /// base'e indir. CheckApiConnection ile aynı mantık.
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

        private string GetApiUrl()
        {
            var normalized = NormalizeBaseUrl(_cachedNgrokUrl);
            if (!string.IsNullOrEmpty(normalized))
                return normalized;
            return DefaultApiUrl;
        }

        /// <summary>
        /// ngrok URL'i çalışmıyorsa localhost'a fallback yapan analiz çağrısı.
        /// </summary>
        private async Task<ThreatAnalysisResult?> TryApiCandidatesAsync(string text)
        {
            var apiUrl = GetApiUrl();
            var result = await TryAnalyzeAtUrlAsync(text, apiUrl);
            if (result != null) return result;

            // Ngrok fail ettiyse localhost'a düş — Flask zaten local çalışıyor olabilir
            if (apiUrl != DefaultApiUrl)
            {
                System.Diagnostics.Debug.WriteLine($"[ML] {apiUrl} failed, falling back to {DefaultApiUrl}");
                result = await TryAnalyzeAtUrlAsync(text, DefaultApiUrl);
            }
            return result;
        }

        public bool AreModelsReady()
        {
            bool legacy = File.Exists(Path.Combine(_modelsPath, "mail_model.pkl")) &&
                          File.Exists(Path.Combine(_modelsPath, "tfidf_vectorizer.pkl"));
            bool named  = File.Exists(Path.Combine(_modelsPath, "phishing_model.pkl")) &&
                          File.Exists(Path.Combine(_modelsPath, "spam_model.pkl")) &&
                          File.Exists(Path.Combine(_modelsPath, "vectorizer.pkl"));
            return legacy || named;
        }

        private async Task<ThreatAnalysisResult?> TryAnalyzeAtUrlAsync(string text, string apiUrl)
        {
            var json = JsonSerializer.Serialize(new { text = text });
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            for (int attempt = 1; attempt <= MaxRetries; attempt++)
            {
                try
                {
                    StatusChanged?.Invoke(this, $"API bağlantısı deneniyor ({attempt}/{MaxRetries})...");

                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    var response = await _httpClient.PostAsync($"{apiUrl}/analyze", content, cts.Token);

                    if (response.IsSuccessStatusCode)
                    {
                        var resultJson = await response.Content.ReadAsStringAsync();
                        using var doc = JsonDocument.Parse(resultJson);
                        var root = doc.RootElement;

                        return new ThreatAnalysisResult
                        {
                            PhishingScore     = root.TryGetProperty("phishing_score",       out var p)  ? p.GetDouble()  : 0,
                            SpamScore         = root.TryGetProperty("spam_score",            out var s)  ? s.GetDouble()  : 0,
                            SqlInjectionScore = root.TryGetProperty("sql_injection_score",   out var sq) ? sq.GetDouble() : 0,
                            XssScore          = root.TryGetProperty("xss_score",             out var x)  ? x.GetDouble()  : 0,
                            TrojanScore       = root.TryGetProperty("trojan_score",           out var tr) ? tr.GetDouble() : 0
                        };
                    }

                    if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                    {
                        StatusChanged?.Invoke(this, "API yetkilendirme hatası!");
                        break;
                    }
                }
                catch (TaskCanceledException)
                {
                    if (attempt < MaxRetries)
                    {
                        StatusChanged?.Invoke(this, "Bağlantı zaman aşımı, yeniden deneniyor...");
                        await Task.Delay(RetryDelayMs);
                    }
                }
                catch (HttpRequestException)
                {
                    if (attempt < MaxRetries)
                    {
                        StatusChanged?.Invoke(this, "Bağlantı hatası, yeniden deneniyor...");
                        await Task.Delay(RetryDelayMs);
                    }
                }
                catch (Exception ex)
                {
                    StatusChanged?.Invoke(this, $"API hatası: {ex.Message}");
                    break;
                }
            }

            return null;
        }

        public async Task<ThreatAnalysisResult> AnalyzeTextAsync(string text, string? attachmentNames = null)
        {
            if (string.IsNullOrWhiteSpace(text))
                return new ThreatAnalysisResult();

            StatusChanged?.Invoke(this, "Analiz başlatılıyor...");

            var apiResult = await TryApiCandidatesAsync(text);
            if (apiResult != null)
            {
                if (!string.IsNullOrEmpty(attachmentNames))
                    apiResult.TrojanScore = Math.Max(apiResult.TrojanScore, CalculateHeuristicTrojan(text, attachmentNames));

                StatusChanged?.Invoke(this,
                    $"Analiz tamamlandı — Phishing: %{apiResult.PhishingScore:F0} | SQL: %{apiResult.SqlInjectionScore:F0} | XSS: %{apiResult.XssScore:F0} | Trojan: %{apiResult.TrojanScore:F0}");
                return apiResult;
            }

            StatusChanged?.Invoke(this, "API yanıt vermiyor, heuristik analiz yapılıyor...");
            return new ThreatAnalysisResult
            {
                PhishingScore     = CalculateHeuristicPhishing(text),
                SpamScore         = CalculateHeuristicSpam(text),
                SqlInjectionScore = CalculateHeuristicSqlInjection(text),
                XssScore          = CalculateHeuristicXss(text),
                TrojanScore       = CalculateHeuristicTrojan(text, attachmentNames ?? "")
            };
        }

        // ── Heuristics ──────────────────────────────────────────────────────────

        public double CalculateHeuristicPhishing(string text)
        {
            text = text.ToLower();
            double score = 0;

            string[] trUrgency = { "acil", "hemen", "son uyarı", "kapatılacak", "askıya", "24 saat",
                                   "iptal edilecek", "zorunlu", "hesabınız", "bloke", "doğrula" };
            foreach (var w in trUrgency) if (text.Contains(w)) score += 15;

            string[] trSensitive = { "şifre", "parola", "kredi kartı", "tc kimlik", "iban",
                                     "banka", "hesap", "yetki", "giriş" };
            foreach (var w in trSensitive) if (text.Contains(w)) score += 20;

            string[] trAction = { "tıkla", "link", "ekteki", "fatura", "indirmek", "giriş yap", "ödeme" };
            foreach (var w in trAction) if (text.Contains(w)) score += 10;

            string[] enUrgency = { "urgent", "immediate action", "account suspended", "verify now",
                                   "click here to restore", "your account will be", "limited access",
                                   "confirm your identity", "unusual activity", "security alert" };
            foreach (var w in enUrgency) if (text.Contains(w)) score += 15;

            string[] enSensitive = { "password", "social security", "credit card", "bank account",
                                     "login credentials", "ssn", "date of birth", "mother's maiden" };
            foreach (var w in enSensitive) if (text.Contains(w)) score += 20;

            string[] enAction = { "click here", "download the attachment", "open the file",
                                  "sign in", "log in to your account", "enter your details" };
            foreach (var w in enAction) if (text.Contains(w)) score += 10;

            if (text.Contains("değerli müşteri") || text.Contains("sayın kullanıcı") ||
                text.Contains("dear customer") || text.Contains("dear user") ||
                text.Contains("dear valued") || text.Contains("sayın abonemiz")) score += 5;

            string[] suspDomains = { "bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly" };
            foreach (var d in suspDomains) if (text.Contains(d)) score += 25;

            return Math.Min(score, 100);
        }

        public double CalculateHeuristicSpam(string text)
        {
            text = text.ToLower();
            double score = 0;

            // predict.py ile senkron — gerçek Türkçe spam mailler üzerinden derlenmiş genişletilmiş liste
            string[] spamWords = {
                // Türkçe
                "bedava", "kampanya", "indirim", "ödül", "kazan", "çekiliş", "fırsat",
                "ucuz", "ucuz fiyat", "alışveriş", "kaçırmayın", "süreli", "sınırlı süre",
                "sadece bugün", "anında", "garanti", "100% garanti", "%100 garanti",
                "para kazan", "kazançlı", "promosyon", "hediye", "kupon",
                // İngilizce
                "special offer", "free", "winner", "congratulations", "prize",
                "you've been selected", "earn money", "make money fast", "work from home",
                "discount", "deal", "bargain", "save money"
            };
            foreach (var w in spamWords) if (text.Contains(w)) score += 15;

            string[] spamPatterns = {
                // Türkçe
                "tıkla", "tıklayın", "ziyaret edin", "burayı tıkla", "hemen al", "hemen satın",
                "sipariş ver", "şimdi al", "kaçırma", "fırsatı kaçırma", "fırsatı kaçırmayın",
                // İngilizce
                "click here", "act now", "limited time", "exclusive deal",
                "don't miss", "no obligation", "risk free", "100% free",
                "satisfaction guaranteed", "this is not spam"
            };
            foreach (var p in spamPatterns) if (text.Contains(p)) score += 20;

            // Yüzde indirim sinyalleri — güçlü spam göstergesi
            string[] percentDiscounts = { "%50", "%60", "%70", "%80", "%90", "%99", "50% off", "70% off", "90% off" };
            foreach (var pd in percentDiscounts) if (text.Contains(pd)) score += 25;

            if (text.Contains("!!!") || text.Contains("???")) score += 10;

            if (text.Contains("buy now") || text.Contains("order now") || text.Contains("subscribe now") ||
                text.Contains("hemen satın") || text.Contains("sipariş ver")) score += 25;

            return Math.Min(score, 100);
        }

        public double CalculateHeuristicSqlInjection(string text)
        {
            text = text.ToLower();
            double score = 0;

            string[] sqlKeywords = {
                "select * from", "select 1 from", "union select", "union all select",
                "drop table", "drop database", "delete from", "insert into",
                "update set", "exec(", "execute(", "xp_cmdshell", "sp_executesql",
                "information_schema", "sys.tables", "@@version", "char(0x",
                "' or '1'='1", "\" or \"1\"=\"1", "or 1=1", "or 1=1--",
                "'; drop", "\"; drop", "' --", "\" --", "'/*", "/**/",
                "sleep(", "waitfor delay", "benchmark(", "load_file(",
                "into outfile", "into dumpfile", "having 1=1"
            };
            foreach (var kw in sqlKeywords) if (text.Contains(kw)) score += 30;

            if (text.Contains("%27") || text.Contains("%22") || text.Contains("%3d")) score += 20;
            if (text.Contains("0x") && (text.Contains("select") || text.Contains("exec"))) score += 25;

            return Math.Min(score, 100);
        }

        public double CalculateHeuristicXss(string text)
        {
            text = text.ToLower();
            double score = 0;

            string[] xssPatterns = {
                "<script", "</script>", "javascript:", "onerror=", "onload=",
                "onclick=", "onmouseover=", "onfocus=", "onblur=",
                "alert(", "confirm(", "prompt(", "document.cookie",
                "document.write(", "window.location", "eval(",
                "<img src=", "<iframe", "<object", "<embed",
                "expression(", "vbscript:", "data:text/html",
                "&#x3c;script", "%3cscript", "\\u003cscript"
            };
            foreach (var p in xssPatterns) if (text.Contains(p)) score += 25;

            if ((text.Contains("&lt;") || text.Contains("&gt;")) &&
                (text.Contains("script") || text.Contains("alert"))) score += 20;

            return Math.Min(score, 100);
        }

        public double CalculateHeuristicTrojan(string text, string attachmentNames)
        {
            string combined = (text + " " + attachmentNames).ToLower();
            double score = 0;

            string[] dangerousExts = {
                ".exe", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
                ".wsf", ".wsh", ".msi", ".ps1", ".scr", ".pif",
                ".com", ".hta", ".jar", ".reg", ".lnk"
            };
            foreach (var ext in dangerousExts) if (combined.Contains(ext)) score += 35;

            if (System.Text.RegularExpressions.Regex.IsMatch(combined,
                @"\.(pdf|doc|xls|zip)\.(exe|bat|vbs|js|cmd)")) score += 40;

            string[] openCues = {
                "ekteki dosyayı açın", "dosyayı çalıştırın", "kurulum dosyası",
                "open the attachment", "run the file", "execute the installer",
                "double-click", "enable macros", "içeriği etkinleştir", "makroları etkinleştir"
            };
            foreach (var c in openCues) if (combined.Contains(c)) score += 20;

            if (combined.Contains("base64") || combined.Contains("powershell -enc") ||
                combined.Contains("powershell -e ") || combined.Contains("cmd /c ")) score += 30;

            return Math.Min(score, 100);
        }

        public bool ShouldMarkAsSpam(double spamScore)        => spamScore >= 50;
        public bool ShouldWarnPhishing(double phishingScore)  => phishingScore >= 40; // 40+ uyarı (40-69 şüpheli, 70+ kritik)
        public bool ShouldWarnSqlInjection(double score)      => score >= 40;
        public bool ShouldWarnXss(double score)               => score >= 40;
        public bool ShouldWarnTrojan(double score)            => score >= 40;
    }
}
