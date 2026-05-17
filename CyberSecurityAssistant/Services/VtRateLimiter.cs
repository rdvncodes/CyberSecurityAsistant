using System;
using System.Collections.Generic;

namespace CyberSecurityAssistant.Services
{
    /// <summary>
    /// VirusTotal free-tier limit: 4 istek/dakika, 500 istek/gün.
    /// Bu sınıf 60 saniyelik sliding window içindeki HTTP isteklerini sayar.
    /// Process içinde tüm VT çağrılarından önce CanMakeRequest() çağrılır.
    /// Limit aşılırsa istek yapılmaz — kullanıcıya kaç saniye beklemesi gerektiği söylenir.
    ///
    /// Not: Tek bir ScanUrlAsync = POST + ~5-10 poll GET = 6-11 istek tüketebilir.
    /// O yüzden poll mantığını da yumuşatmak gerek (her poll GET'i ayrı istek sayar).
    /// </summary>
    public static class VtRateLimiter
    {
        private static readonly Queue<DateTime> _requestTimes = new();
        private static readonly object _lock = new();
        private const int MaxRequestsPerMinute = 4;
        private const int WindowSeconds = 60;

        /// <summary>Yeni bir istek yapma izni verir mi?</summary>
        public static bool CanMakeRequest()
        {
            lock (_lock)
            {
                PruneOld();
                return _requestTimes.Count < MaxRequestsPerMinute;
            }
        }

        /// <summary>İstek yapıldıktan sonra çağrılır — pencereye timestamp eklenir.</summary>
        public static void RecordRequest()
        {
            lock (_lock)
            {
                _requestTimes.Enqueue(DateTime.UtcNow);
                PruneOld();
            }
        }

        /// <summary>Yeni bir slot için kaç saniye beklemek gerek?</summary>
        public static int SecondsUntilNextSlot()
        {
            lock (_lock)
            {
                PruneOld();
                if (_requestTimes.Count < MaxRequestsPerMinute) return 0;
                // En eski isteği penceredan çıkmaya kadarki süre
                DateTime oldest = _requestTimes.Peek();
                DateTime slotFreeAt = oldest.AddSeconds(WindowSeconds);
                double wait = (slotFreeAt - DateTime.UtcNow).TotalSeconds;
                return Math.Max(1, (int)Math.Ceiling(wait));
            }
        }

        /// <summary>Şu an penceredeki istek sayısı (debug için).</summary>
        public static int CurrentCount()
        {
            lock (_lock)
            {
                PruneOld();
                return _requestTimes.Count;
            }
        }

        private static void PruneOld()
        {
            DateTime cutoff = DateTime.UtcNow.AddSeconds(-WindowSeconds);
            while (_requestTimes.Count > 0 && _requestTimes.Peek() < cutoff)
                _requestTimes.Dequeue();
        }
    }
}
