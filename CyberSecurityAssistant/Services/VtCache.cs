using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace CyberSecurityAssistant.Services
{
    /// <summary>
    /// VirusTotal yanıtları için 24 saatlik (yapılandırılabilir) lokal cache.
    /// Aynı URL veya dosya hash'i tekrar taranırsa VT API'sine gidilmez —
    /// hem rate limit korunur (4 req/dk) hem yanıt anında gelir.
    ///
    /// cache_key:
    ///   - URL için: SHA-256(normalized_url)
    ///   - Dosya için: SHA-256(file_content) — VT zaten hash kullanıyor
    /// </summary>
    public static class VtCache
    {
        /// <summary>
        /// Cache'de geçerli bir kayıt varsa döndürür. Yoksa veya süresi geçmişse null.
        /// </summary>
        public static VTScanResult? TryGet(string cacheKey, string scanType, int maxAgeHours = 24)
        {
            if (string.IsNullOrWhiteSpace(cacheKey)) return null;

            try
            {
                using var connection = DatabaseHelper.GetConnection();
                var cmd = connection.CreateCommand();
                cmd.CommandText = @"
                    SELECT malicious, suspicious, harmless, undetected, vendor_json, threat_type, cached_at
                    FROM vt_cache
                    WHERE cache_key = @key AND scan_type = @type";
                cmd.Parameters.AddWithValue("@key", cacheKey);
                cmd.Parameters.AddWithValue("@type", scanType);

                using var reader = cmd.ExecuteReader();
                if (!reader.Read()) return null;

                // TTL kontrolü
                string cachedAtStr = reader.IsDBNull(6) ? "" : reader.GetString(6);
                if (DateTime.TryParse(cachedAtStr, out DateTime cachedAt))
                {
                    var age = DateTime.UtcNow - cachedAt.ToUniversalTime();
                    if (age.TotalHours > maxAgeHours)
                    {
                        Debug.WriteLine($"[VtCache] Stale (age {age.TotalHours:F1}h > {maxAgeHours}h): {cacheKey}");
                        return null;
                    }
                }

                var result = new VTScanResult
                {
                    Malicious  = reader.GetInt32(0),
                    Suspicious = reader.GetInt32(1),
                    Harmless   = reader.GetInt32(2),
                    Undetected = reader.GetInt32(3)
                };

                // Vendor details JSON'unu deserialize et
                string vendorJson = reader.IsDBNull(4) ? "" : reader.GetString(4);
                if (!string.IsNullOrWhiteSpace(vendorJson))
                {
                    try
                    {
                        var vendors = JsonSerializer.Deserialize<List<VendorResult>>(vendorJson);
                        if (vendors != null) result.VendorDetails = vendors;
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"[VtCache] Vendor JSON parse hatası: {ex.Message}");
                    }
                }

                Debug.WriteLine($"[VtCache] HIT — key={cacheKey.Substring(0, Math.Min(16, cacheKey.Length))}..., {result.Malicious}/{result.TotalEngines}");
                return result;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[VtCache] TryGet hatası: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Yeni VT yanıtını cache'e ekler veya günceller (INSERT OR REPLACE).
        /// </summary>
        public static void Set(string cacheKey, string scanType, VTScanResult result)
        {
            if (string.IsNullOrWhiteSpace(cacheKey) || result == null) return;
            if (!string.IsNullOrEmpty(result.ErrorMessage)) return; // hatalı sonucu cache'leme
            if (result.IsRateLimited) return;

            try
            {
                string vendorJson;
                try { vendorJson = JsonSerializer.Serialize(result.VendorDetails); }
                catch { vendorJson = "[]"; }

                using var connection = DatabaseHelper.GetConnection();
                var cmd = connection.CreateCommand();
                cmd.CommandText = @"
                    INSERT OR REPLACE INTO vt_cache
                        (cache_key, scan_type, malicious, suspicious, harmless, undetected,
                         vendor_json, threat_type, cached_at)
                    VALUES (@key, @type, @m, @s, @h, @u, @vj, @tt, @at)";
                cmd.Parameters.AddWithValue("@key", cacheKey);
                cmd.Parameters.AddWithValue("@type", scanType);
                cmd.Parameters.AddWithValue("@m", result.Malicious);
                cmd.Parameters.AddWithValue("@s", result.Suspicious);
                cmd.Parameters.AddWithValue("@h", result.Harmless);
                cmd.Parameters.AddWithValue("@u", result.Undetected);
                cmd.Parameters.AddWithValue("@vj", vendorJson);
                cmd.Parameters.AddWithValue("@tt", result.TopThreatType() ?? "");
                cmd.Parameters.AddWithValue("@at", DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"));
                cmd.ExecuteNonQuery();
                Debug.WriteLine($"[VtCache] STORED — key={cacheKey.Substring(0, Math.Min(16, cacheKey.Length))}..., {result.Malicious}/{result.TotalEngines}");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[VtCache] Set hatası: {ex.Message}");
            }
        }

        /// <summary>Eski cache kayıtlarını temizler (TTL aşmış olanlar).</summary>
        public static int PurgeExpired(int maxAgeHours = 24)
        {
            try
            {
                using var connection = DatabaseHelper.GetConnection();
                var cmd = connection.CreateCommand();
                cmd.CommandText = @"
                    DELETE FROM vt_cache
                    WHERE cached_at < @cutoff";
                cmd.Parameters.AddWithValue("@cutoff",
                    DateTime.UtcNow.AddHours(-maxAgeHours).ToString("yyyy-MM-dd HH:mm:ss"));
                return cmd.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[VtCache] Purge hatası: {ex.Message}");
                return 0;
            }
        }

        public static int Count()
        {
            try
            {
                using var connection = DatabaseHelper.GetConnection();
                var cmd = connection.CreateCommand();
                cmd.CommandText = "SELECT COUNT(*) FROM vt_cache";
                return Convert.ToInt32(cmd.ExecuteScalar());
            }
            catch { return 0; }
        }
    }
}
