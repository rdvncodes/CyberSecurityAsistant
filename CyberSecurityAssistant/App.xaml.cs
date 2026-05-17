using System;
using System.Diagnostics;
using System.Threading;
using System.Windows;

namespace CyberSecurityAssistant
{
    public partial class App : System.Windows.Application
    {
        // Aynı kullanıcı için tekil instance — mevcut bir kopya varsa
        // bu kopya başlamadan kapanır (sistem tepsisinde duran kopya etkilenmez).
        // Local\ prefix → sistem geneli değil, sadece bu kullanıcı için.
        private const string MutexName = "Local\\CyberSecurityAssistant.SingleInstance.v2";
        private static Mutex? _mutex;
        private bool _mutexOwned = false;

        protected override void OnStartup(StartupEventArgs e)
        {
            // Mutex'i NON-OWNED olarak yarat, sonra WaitOne(0) ile sahiplenmeyi dene.
            // Bu yaklaşım abandoned (önceki crash sonrası temizlenmemiş) mutex'i de doğru ele alır.
            _mutex = new Mutex(initiallyOwned: false, MutexName);

            bool acquired = false;
            try
            {
                // 0 timeout = "ya hemen sahip ol ya da kaybet"
                acquired = _mutex.WaitOne(TimeSpan.Zero, exitContext: false);
            }
            catch (AbandonedMutexException)
            {
                // Önceki sahip process crash'le kapanmış — biz mutex'i devraldık, devam edebiliriz.
                Debug.WriteLine("[App] Abandoned mutex devralındı (önceki instance crash'le kapanmış)");
                acquired = true;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[App] Mutex WaitOne exception: {ex.Message}");
                // Şüpheli durumda — yine de açmaya izin ver (daha az kullanıcı acısı)
                acquired = true;
            }

            if (!acquired)
            {
                // Başka bir LIVE instance gerçekten çalışıyor — kapatmamız gerek.
                // Ama önce gerçekten process var mı diye doğrulayalım — emin olalım.
                var liveProcesses = Process.GetProcessesByName("CyberSecurityAssistant");
                int otherPidCount = 0;
                foreach (var p in liveProcesses)
                {
                    try { if (p.Id != Environment.ProcessId) otherPidCount++; } catch { }
                    p.Dispose();
                }

                if (otherPidCount == 0)
                {
                    // Process listesinde başka instance yok ama mutex bizi engelliyor.
                    // Bu durum çok nadirdir — kullanıcı acısı pahasına geçit ver.
                    Debug.WriteLine("[App] Mutex blokluyor ama başka process yok — devam et");
                    _mutex.Dispose();
                    _mutex = null;
                    base.OnStartup(e);
                    return;
                }

                System.Windows.MessageBox.Show(
                    "Siber Mail & Güvenlik Asistanı zaten çalışıyor.\nSistem tepsisindeki kalkan ikonuna sağ tıklayarak ulaşabilirsiniz.",
                    "Uygulama Zaten Açık",
                    System.Windows.MessageBoxButton.OK,
                    System.Windows.MessageBoxImage.Information);
                Shutdown();
                return;
            }

            _mutexOwned = true;
            base.OnStartup(e);
        }

        protected override void OnExit(ExitEventArgs e)
        {
            // Flask child process'i kapat (varsa) — orphan kalmasın
            try { Services.FlaskServiceLauncher.Stop(); } catch { }

            // Mutex'i sahipsek serbest bırak; zaten serbestse exception yutulur.
            if (_mutexOwned)
            {
                try { _mutex?.ReleaseMutex(); } catch { /* zaten serbest */ }
            }
            _mutex?.Dispose();
            base.OnExit(e);
        }
    }
}
