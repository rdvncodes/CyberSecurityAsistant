using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using CyberSecurityAssistant;

namespace CyberSecurityAssistant.Services
{
    public class VTScanResult
    {
        public int Malicious { get; set; }
        public int Undetected { get; set; }
        public int Suspicious { get; set; }
        public int Harmless { get; set; }
        public string ErrorMessage { get; set; } = "";
        public bool IsRateLimited { get; set; }
        public List<VendorResult> VendorDetails { get; set; } = new();

        /// <summary>Toplam motor sayısı — "9/74" gösteriminde paydadır.</summary>
        public int TotalEngines => Malicious + Suspicious + Harmless + Undetected;

        /// <summary>
        /// Vendor sonuçlarından tehdit tipini (Trojan, Phishing, Adware vb.) çıkarır.
        /// En sık geçen birinci kelimeyi döner: "Trojan.Win32.X" → "Trojan"
        /// </summary>
        public string TopThreatType()
        {
            if (VendorDetails == null || VendorDetails.Count == 0) return "";
            var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var v in VendorDetails)
            {
                if (v.Category != "malicious" && v.Category != "suspicious") continue;
                if (string.IsNullOrWhiteSpace(v.Result)) continue;
                // Türkçe etiketleri ("Tehdit", "Şüpheli") atla — gerçek VT result'u arıyoruz
                if (v.Result == "Tehdit" || v.Result == "Temiz" || v.Result == "Şüpheli") continue;

                string type = v.Result.Split(new[] { '.', '-', ':', '/', '_', ' ' }, 2)[0].Trim();
                if (type.Length < 3) continue;
                counts[type] = counts.TryGetValue(type, out int n) ? n + 1 : 1;
            }
            if (counts.Count == 0) return "";
            return counts.OrderByDescending(kv => kv.Value).First().Key;
        }
    }

    public class VirusTotalService
    {
        private static readonly HttpClient _httpClient = new HttpClient();

        public static async Task<VTScanResult?> ScanHashAsync(string fileHash, string apiKey)
        {
            if (string.IsNullOrWhiteSpace(fileHash))
                return new VTScanResult { ErrorMessage = "Dosya hash'i boş" };

            // 1) ÖNCE LOKAL CACHE — 24 saatlik TTL, aynı dosya tekrar taranınca VT'ye gitme.
            //    Quota korunur, anında sonuç.
            int cacheHours = AppConfig.Settings.VirusTotalCacheHours;
            var cached = VtCache.TryGet(fileHash, "file", cacheHours);
            if (cached != null)
            {
                System.Diagnostics.Debug.WriteLine($"[VT] Cache HIT (file): {fileHash.Substring(0, 16)}...");
                return cached;
            }

            // 2) Cache miss — VT'ye sor
            var fresh = await ExecuteVTRequest($"https://www.virustotal.com/api/v3/files/{fileHash}", apiKey);

            // 3) Başarılıysa cache'e koy (hata/rate-limit cache'lenmez)
            if (fresh != null && string.IsNullOrEmpty(fresh.ErrorMessage) && !fresh.IsRateLimited && fresh.TotalEngines > 0)
            {
                VtCache.Set(fileHash, "file", fresh);
            }

            return fresh;
        }

        /// <summary>
        /// URL'i URL-safe Base64'e çevirir (VT API v3'ün /urls/{id} endpoint için).
        /// "https://google.com" → "aHR0cHM6Ly9nb29nbGUuY29t"
        /// </summary>
        private static string ToVtUrlId(string url)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(url))
                          .Replace("+", "-").Replace("/", "_").TrimEnd('=');
        }

        public static async Task<VTScanResult?> ScanUrlAsync(string url, string apiKey)
        {
            if (string.IsNullOrEmpty(url))
                return new VTScanResult { ErrorMessage = "URL boş" };

            string normalizedUrl = NormalizeUrl(url);
            if (string.IsNullOrEmpty(normalizedUrl))
                return new VTScanResult { ErrorMessage = "Geçersiz URL formatı" };

            // 0) LOKAL CACHE — 24 saatlik TTL. Aynı URL kısa süre içinde tekrar taranınca
            //    VT'ye hiç gitmeyiz. Quota tasarrufu + anlık yanıt.
            int cacheHours = AppConfig.Settings.VirusTotalCacheHours;
            var localCached = VtCache.TryGet(normalizedUrl, "url", cacheHours);
            if (localCached != null)
            {
                System.Diagnostics.Debug.WriteLine($"[VT] Lokal cache HIT: {normalizedUrl}");
                return localCached;
            }

            // STRATEJİ:
            // 1) Önce GET /urls/{id} ile VT'nin kendi cache'inden dene — popüler URL'ler 1 isteğe iner.
            // 2) 404 dönerse URL yeni demek → POST /urls + polling (4-6 istek)
            string urlId = ToVtUrlId(normalizedUrl);
            var vtCached = await ExecuteVTRequest($"https://www.virustotal.com/api/v3/urls/{urlId}", apiKey);
            if (vtCached != null)
            {
                if (vtCached.IsRateLimited) return vtCached; // rate limit hemen dön
                if (string.IsNullOrEmpty(vtCached.ErrorMessage) && vtCached.TotalEngines > 0)
                {
                    System.Diagnostics.Debug.WriteLine($"[VT] VT cache HIT for {normalizedUrl} (1 request)");
                    // Lokal cache'e de yaz — sonraki çağrıda VT'ye bile gitmesin
                    VtCache.Set(normalizedUrl, "url", vtCached);
                    return vtCached;
                }
                // ErrorMessage "Veritabanında bulunamadı" ise devam et (404)
            }

            // Yerel rate limit kontrolü — POST yapmaya niyet edersek 4-6 istek alacak
            if (!VtRateLimiter.CanMakeRequest())
            {
                int wait = VtRateLimiter.SecondsUntilNextSlot();
                return new VTScanResult
                {
                    IsRateLimited = true,
                    ErrorMessage = $"VT free limit aşıldı ({VtRateLimiter.CurrentCount()}/4 dk). {wait}s bekleyin."
                };
            }

            try
            {
                System.Diagnostics.Debug.WriteLine($"VT Debug - Submitting URL (not cached): {normalizedUrl}");

                using var request = new HttpRequestMessage(HttpMethod.Post, "https://www.virustotal.com/api/v3/urls");
                request.Headers.Add("x-apikey", apiKey);
                request.Headers.Add("accept", "application/json");

                var content = new StringContent($"url={Uri.EscapeDataString(normalizedUrl)}", Encoding.UTF8, "application/x-www-form-urlencoded");
                request.Content = content;

                VtRateLimiter.RecordRequest();
                var response = await _httpClient.SendAsync(request);

                System.Diagnostics.Debug.WriteLine($"VT Debug - Submit Response Status: {response.StatusCode}");

                if (!response.IsSuccessStatusCode)
                {
                    string errorBody = await response.Content.ReadAsStringAsync();
                    string errorMsg = ParseVtError(errorBody);
                    System.Diagnostics.Debug.WriteLine($"VT Debug - Submit Error: {errorBody}");

                    if (response.StatusCode == (System.Net.HttpStatusCode)429)
                    {
                        return new VTScanResult { IsRateLimited = true, ErrorMessage = "Rate limit aşıldı, lütfen bekleyin" };
                    }
                    return new VTScanResult { ErrorMessage = $"API Hatası: {response.StatusCode} - {errorMsg}" };
                }

                var jsonResponse = await response.Content.ReadAsStringAsync();
                System.Diagnostics.Debug.WriteLine($"VT Debug - Submit Response: {jsonResponse.Substring(0, Math.Min(500, jsonResponse.Length))}");

                // Defensive parsing — VT bazen beklenmedik şema dönebilir, çökmeyelim
                string? analysisId = null;
                try
                {
                    using var doc = JsonDocument.Parse(jsonResponse);
                    if (doc.RootElement.TryGetProperty("data", out var dataEl) &&
                        dataEl.TryGetProperty("id", out var idEl) &&
                        idEl.ValueKind == JsonValueKind.String)
                    {
                        analysisId = idEl.GetString();
                    }
                }
                catch (JsonException jex)
                {
                    return new VTScanResult { ErrorMessage = $"VT yanıtı parse edilemedi: {jex.Message}" };
                }

                if (string.IsNullOrEmpty(analysisId))
                {
                    return new VTScanResult { ErrorMessage = "VT'den analiz ID alınamadı (beklenmedik yanıt formatı)" };
                }

                System.Diagnostics.Debug.WriteLine($"VT Debug - Analysis ID: {analysisId}");
                var pollResult = await PollAnalysisResultAsync(analysisId, apiKey);

                // Başarılı sonucu lokal cache'e yaz (sonraki çağrılarda VT'ye gitmemek için)
                if (pollResult != null && string.IsNullOrEmpty(pollResult.ErrorMessage)
                    && !pollResult.IsRateLimited && pollResult.TotalEngines > 0)
                {
                    VtCache.Set(normalizedUrl, "url", pollResult);
                }
                return pollResult;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"VT URL Submit Hatası: {ex.Message}");
                return new VTScanResult { ErrorMessage = ex.Message };
            }
        }

        private static string NormalizeUrl(string url)
        {
            url = url.Trim();
            if (string.IsNullOrEmpty(url))
                return "";

            if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                url = "https://" + url;
            }

            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
                (uri.Scheme != "http" && uri.Scheme != "https"))
            {
                return "";
            }

            return uri.ToString();
        }

        private static string ParseVtError(string json)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("error", out var error))
                {
                    return error.GetProperty("message").GetString() ?? "Bilinmeyen hata";
                }
            }
            catch { }
            return json.Length > 200 ? json.Substring(0, 200) : json;
        }

        private static async Task<VTScanResult?> PollAnalysisResultAsync(string analysisId, string apiKey)
        {
            // Free tier 4 req/min limiti — daha az ve yumuşak polling.
            // 3 retry × 4, 7, 12 sn = max 23sn ama yalnızca 3 GET (toplam POST + 3 GET = 4 istek).
            // Google gibi popüler URL'ler 2. poll'da tamamlanır.
            int maxRetries = 3;
            int[] delaysMs = { 4000, 7000, 12000 };

            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                // Her poll GET'i ayrı bir VT request — rate limit kontrolü
                if (!VtRateLimiter.CanMakeRequest())
                {
                    int wait = VtRateLimiter.SecondsUntilNextSlot();
                    System.Diagnostics.Debug.WriteLine($"[VT Poll {attempt}] Rate limit, {wait}s bekleniyor");
                    return new VTScanResult
                    {
                        IsRateLimited = true,
                        ErrorMessage = $"VT polling rate limit. {wait}s bekleyin."
                    };
                }

                try
                {
                    using var request = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/analyses/{analysisId}");
                    request.Headers.Add("x-apikey", apiKey);
                    request.Headers.Add("accept", "application/json");

                    VtRateLimiter.RecordRequest();
                    var response = await _httpClient.SendAsync(request);

                    if (response.StatusCode == (System.Net.HttpStatusCode)429)
                    {
                        // VT sunucu tarafı rate limit — yerel sayacı da güncel tut
                        return new VTScanResult
                        {
                            IsRateLimited = true,
                            ErrorMessage = "VT sunucu rate limit (HTTP 429) — 1 dk bekleyin"
                        };
                    }

                    if (!response.IsSuccessStatusCode)
                    {
                        string errorBody = await response.Content.ReadAsStringAsync();
                        System.Diagnostics.Debug.WriteLine($"VT Analysis Error: {response.StatusCode} - {errorBody}");
                        return new VTScanResult { ErrorMessage = $"Analiz sorgulama hatası: {response.StatusCode}" };
                    }

                    var jsonResponse = await response.Content.ReadAsStringAsync();

                    // Defensive parsing — beklenmedik şema gelirse çökme, hata mesajı dön
                    JsonDocument doc;
                    try { doc = JsonDocument.Parse(jsonResponse); }
                    catch (JsonException jex)
                    {
                        return new VTScanResult { ErrorMessage = $"VT analiz yanıtı parse edilemedi: {jex.Message}" };
                    }

                    using (doc)
                    {
                        if (!doc.RootElement.TryGetProperty("data", out var data) ||
                            !data.TryGetProperty("attributes", out var attributes))
                        {
                            return new VTScanResult { ErrorMessage = "VT yanıtında 'data.attributes' bulunamadı" };
                        }

                        string status = "unknown";
                        if (attributes.TryGetProperty("status", out var statusProp) &&
                            statusProp.ValueKind == JsonValueKind.String)
                        {
                            status = statusProp.GetString() ?? "unknown";
                        }

                        System.Diagnostics.Debug.WriteLine($"VT Debug - Attempt {attempt}/{maxRetries}, Status: {status}");

                        if (status == "completed")
                        {
                            // /analyses/{id} cevabı 'stats' ve 'results' anahtarlarını kullanır.
                            if (!attributes.TryGetProperty("stats", out var stats))
                            {
                                return new VTScanResult { ErrorMessage = "VT yanıtında 'stats' bulunamadı" };
                            }

                        var vtResult = new VTScanResult
                        {
                            Malicious = stats.TryGetProperty("malicious", out var m) ? m.GetInt32() : 0,
                            Undetected = stats.TryGetProperty("undetected", out var u) ? u.GetInt32() : 0,
                            Suspicious = stats.TryGetProperty("suspicious", out var s) ? s.GetInt32() : 0,
                            Harmless = stats.TryGetProperty("harmless", out var h) ? h.GetInt32() : 0
                        };

                        System.Diagnostics.Debug.WriteLine($"VT Debug - Malicious: {vtResult.Malicious}, Undetected: {vtResult.Undetected}, Suspicious: {vtResult.Suspicious}, Harmless: {vtResult.Harmless}");

                            if (attributes.TryGetProperty("results", out var results) &&
                                results.ValueKind == JsonValueKind.Object)
                            {
                                foreach (var vendor in results.EnumerateObject())
                                {
                                    string vendorName = vendor.Name;
                                    // Defensive: category yoksa "unknown" varsay
                                    string category = vendor.Value.TryGetProperty("category", out var catEl)
                                        ? catEl.GetString() ?? "unknown"
                                        : "unknown";
                                    string actualResult = vendor.Value.TryGetProperty("result", out var rs)
                                        ? rs.GetString() ?? ""
                                        : "";

                                    vtResult.VendorDetails.Add(new VendorResult
                                    {
                                        Name = vendorName,
                                        Category = category,
                                        Result = !string.IsNullOrEmpty(actualResult) ? actualResult
                                               : (category == "malicious" ? "Tehdit"
                                                  : category == "undetected" ? "Temiz"
                                                  : "Şüpheli")
                                    });
                                }
                            }

                            return vtResult;
                        }
                        else
                        {
                            int delay = delaysMs[Math.Min(attempt - 1, delaysMs.Length - 1)];
                            System.Diagnostics.Debug.WriteLine($"Analiz henüz tamamlanmadı: {status}, deneme {attempt}/{maxRetries}, {delay}ms bekleniyor");
                            await Task.Delay(delay);
                        }
                    } // using (doc)
                }
                catch (Exception ex)
                {
                    int delay = delaysMs[Math.Min(attempt - 1, delaysMs.Length - 1)];
                    System.Diagnostics.Debug.WriteLine($"Poll Hatası (deneme {attempt}): {ex.Message}");
                    await Task.Delay(delay);
                }
            }

            return new VTScanResult { ErrorMessage = "Analiz zaman aşımı (VT 5 denemede tamamlanmadı)" };
        }

        private static async Task<VTScanResult?> ExecuteVTRequest(string endpoint, string apiKey)
        {
            // Yerel rate limit kontrolü (4 req/min)
            if (!VtRateLimiter.CanMakeRequest())
            {
                int wait = VtRateLimiter.SecondsUntilNextSlot();
                return new VTScanResult
                {
                    IsRateLimited = true,
                    ErrorMessage = $"VT free limit aşıldı ({VtRateLimiter.CurrentCount()}/4 dk). {wait}s bekleyin."
                };
            }

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
                request.Headers.Add("x-apikey", apiKey);
                request.Headers.Add("accept", "application/json");

                VtRateLimiter.RecordRequest();
                var response = await _httpClient.SendAsync(request);

                if (!response.IsSuccessStatusCode)
                {
                    if (response.StatusCode == (System.Net.HttpStatusCode)429)
                    {
                        return new VTScanResult { IsRateLimited = true, ErrorMessage = "Rate limit aşıldı, lütfen bekleyin" };
                    }
                    if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                    {
                        return new VTScanResult { ErrorMessage = "Veritabanında bulunamadı" };
                    }
                    return new VTScanResult { ErrorMessage = $"API Hatası: {response.StatusCode}" };
                }

                var jsonResponse = await response.Content.ReadAsStringAsync();

                // Defensive parsing — şema beklenmediği gibiyse çökme, anlamlı hata dön
                JsonDocument? doc = null;
                try { doc = JsonDocument.Parse(jsonResponse); }
                catch (JsonException jex)
                {
                    return new VTScanResult { ErrorMessage = $"VT yanıtı parse edilemedi: {jex.Message}" };
                }

                using (doc)
                {
                    if (!doc.RootElement.TryGetProperty("data", out var rootData) ||
                        !rootData.TryGetProperty("attributes", out var attributes))
                    {
                        return new VTScanResult { ErrorMessage = "VT yanıtı 'data.attributes' içermiyor" };
                    }
                    if (!attributes.TryGetProperty("last_analysis_stats", out var stats))
                    {
                        return new VTScanResult { ErrorMessage = "VT yanıtı 'last_analysis_stats' içermiyor" };
                    }
                    attributes.TryGetProperty("last_analysis_results", out var results);

                    var vtResult = new VTScanResult
                    {
                        Malicious = stats.TryGetProperty("malicious", out var mEl) ? mEl.GetInt32() : 0,
                        Undetected = stats.TryGetProperty("undetected", out var uEl) ? uEl.GetInt32() : 0,
                        Suspicious = stats.TryGetProperty("suspicious", out var sEl) ? sEl.GetInt32() : 0,
                        Harmless = stats.TryGetProperty("harmless", out var hf) ? hf.GetInt32() : 0
                    };

                    // results bulunamadıysa atla — vendor detayı olmasa da skor zaten alındı
                    if (results.ValueKind == JsonValueKind.Object)
                    {
                        foreach (var vendor in results.EnumerateObject())
                        {
                            string vendorName = vendor.Name;
                            // Defensive: category yoksa "unknown"
                            string category = vendor.Value.TryGetProperty("category", out var catEl)
                                ? catEl.GetString() ?? "unknown"
                                : "unknown";
                            string actualResult = vendor.Value.TryGetProperty("result", out var rf)
                                ? rf.GetString() ?? ""
                                : "";

                            vtResult.VendorDetails.Add(new VendorResult
                            {
                                Name = vendorName,
                                Category = category,
                                Result = !string.IsNullOrEmpty(actualResult) ? actualResult
                                       : (category == "malicious" ? "Tehdit"
                                          : category == "undetected" ? "Temiz"
                                          : "Şüpheli")
                            });
                        }
                    }
                    return vtResult;
                } // using (doc)
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"VT API Hatası: {ex.Message}");
                return new VTScanResult { ErrorMessage = ex.Message };
            }
        }
    }
}
