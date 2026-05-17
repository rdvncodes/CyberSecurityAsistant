using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;

namespace CyberSecurityAssistant.Services
{
    /// <summary>
    /// appsettings.json'ı yükleyen statik konfigürasyon servisi.
    /// Hardcoded değerleri (token, URL, timeout) merkezi tutar.
    /// Dosya bulunmaz veya parse edilemezse güvenli varsayılan değerler döner.
    /// İlk erişimde lazy load eder.
    /// </summary>
    public static class AppConfig
    {
        private static AppSettings? _settings;
        private static readonly object _lock = new();

        public static AppSettings Settings
        {
            get
            {
                if (_settings != null) return _settings;
                lock (_lock)
                {
                    if (_settings == null) _settings = Load();
                    return _settings;
                }
            }
        }

        private static AppSettings Load()
        {
            string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "appsettings.json");
            if (!File.Exists(path))
            {
                Debug.WriteLine($"[AppConfig] appsettings.json bulunamadı: {path} — varsayılan değerler kullanılıyor");
                return new AppSettings();
            }
            try
            {
                string json = File.ReadAllText(path);
                var settings = JsonSerializer.Deserialize<AppSettings>(json,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                return settings ?? new AppSettings();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[AppConfig] appsettings.json parse edilemedi: {ex.Message} — varsayılan değerler");
                return new AppSettings();
            }
        }

        /// <summary>Test/yeniden yükleme için cache'i temizler.</summary>
        public static void Reload()
        {
            lock (_lock) { _settings = null; }
        }
    }

    public class AppSettings
    {
        // appsettings.json yoksa veya alan eksikse bu varsayılan değerler kullanılır
        public string InternalApiAuthToken { get; set; } = "SiberSahin-Auth-Token";
        public string FlaskApiUrl { get; set; } = "http://localhost:5000";
        public int VirusTotalCacheHours { get; set; } = 24;
        public string DefaultLanguage { get; set; } = "TR";

        public VtSettings Vt { get; set; } = new VtSettings();
        public GmailSettings Gmail { get; set; } = new GmailSettings();
    }

    public class VtSettings
    {
        public int RateLimitPerMinute { get; set; } = 4;
        public int PollMaxRetries { get; set; } = 3;
        public int ConnectTimeoutSeconds { get; set; } = 30;
    }

    public class GmailSettings
    {
        public string ImapServer { get; set; } = "imap.gmail.com";
        public int ImapPort { get; set; } = 993;
        public string SmtpServer { get; set; } = "smtp.gmail.com";
        public int SmtpPort { get; set; } = 587;
    }
}
