using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

namespace CyberSecurityAssistant.Services
{
    /// <summary>
    /// predict.py Flask servisini WPF app yaşam döngüsüne bağlar:
    /// - Uygulama açılışında /health pingleyip Flask çalışıyor mu kontrol eder
    /// - Çalışmıyorsa python predict.py'ı çocuk process olarak başlatır
    /// - Uygulama kapanışında child process'i öldürür (orphan kalmasın)
    /// - Zaten dışarıdan çalışıyorsa duplicate açmaz, hızlıca devam eder
    /// </summary>
    public static class FlaskServiceLauncher
    {
        private static Process? _flaskProcess;
        private static readonly object _lock = new object();
        private static readonly HttpClient _healthClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(2)
        };

        public const string DefaultUrl = "http://localhost:5000";

        /// <summary>
        /// Flask hazır mı kontrol eder. Çalışıyorsa true. Çalışmıyorsa başlatır ve
        /// /health 200 dönene kadar bekler (max ~15 sn). Başlatamaz veya cevap vermezse false.
        /// </summary>
        public static async Task<bool> EnsureRunningAsync(string apiUrl = DefaultUrl, Action<string>? statusCallback = null)
        {
            // 1) Zaten çalışıyor mu?
            if (await IsFlaskRunningAsync(apiUrl))
            {
                statusCallback?.Invoke("Flask zaten çalışıyor — yeniden başlatılmayacak");
                return true;
            }

            statusCallback?.Invoke("Flask başlatılıyor...");

            // 2) ÖNCE PyInstaller ile derlenmiş predict.exe ara — varsa onu kullan.
            //    Python kurulu olmasa bile çalışır (tüm bağımlılıklar bundle içinde).
            string? predictExe = FindPredictExe();
            ProcessStartInfo? psi = null;
            string label;

            if (predictExe != null)
            {
                label = "predict.exe (bundle)";
                Debug.WriteLine($"[FlaskLauncher] PyInstaller exe bulundu: {predictExe}");
                psi = new ProcessStartInfo
                {
                    FileName = predictExe,
                    WorkingDirectory = Path.GetDirectoryName(predictExe) ?? Directory.GetCurrentDirectory(),
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
            }
            else
            {
                // 3) Fallback: predict.py + sistem Python'ı
                string? predictPy = FindPredictPy();
                if (predictPy == null)
                {
                    statusCallback?.Invoke("predict.exe ve predict.py bulunamadı");
                    return false;
                }
                string? pythonExe = FindPythonExecutable();
                if (pythonExe == null)
                {
                    statusCallback?.Invoke("Python yorumlayıcısı bulunamadı (predict.exe da yok)");
                    return false;
                }

                label = $"python {Path.GetFileName(predictPy)}";
                psi = new ProcessStartInfo
                {
                    FileName = pythonExe,
                    Arguments = $"\"{predictPy}\"",
                    WorkingDirectory = Path.GetDirectoryName(predictPy) ?? Directory.GetCurrentDirectory(),
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                psi.EnvironmentVariables["PYTHONIOENCODING"] = "utf-8";
                psi.EnvironmentVariables["PYTHONUNBUFFERED"] = "1";
            }

            try
            {

                lock (_lock)
                {
                    _flaskProcess = Process.Start(psi);
                }

                if (_flaskProcess == null)
                {
                    statusCallback?.Invoke("Flask process başlatılamadı");
                    return false;
                }

                Debug.WriteLine($"[FlaskLauncher] Process başlatıldı: PID={_flaskProcess.Id}, mode={label}");

                // Process çıktısını debug'a yönlendir (background)
                _ = Task.Run(async () =>
                {
                    try
                    {
                        while (_flaskProcess != null && !_flaskProcess.HasExited)
                        {
                            string? line = await _flaskProcess.StandardOutput.ReadLineAsync();
                            if (line == null) break;
                            Debug.WriteLine($"[Flask] {line}");
                        }
                    }
                    catch { /* process killed */ }
                });
                _ = Task.Run(async () =>
                {
                    try
                    {
                        while (_flaskProcess != null && !_flaskProcess.HasExited)
                        {
                            string? line = await _flaskProcess.StandardError.ReadLineAsync();
                            if (line == null) break;
                            Debug.WriteLine($"[Flask STDERR] {line}");
                        }
                    }
                    catch { }
                });

                // 5) Health endpoint hazır olana kadar bekle (max 15 sn)
                for (int i = 1; i <= 15; i++)
                {
                    await Task.Delay(1000);

                    // Process erken çıkmış mı?
                    if (_flaskProcess.HasExited)
                    {
                        statusCallback?.Invoke($"Flask {_flaskProcess.ExitCode} kodu ile çıktı");
                        Debug.WriteLine($"[FlaskLauncher] Process erken çıktı (kod {_flaskProcess.ExitCode})");
                        return false;
                    }

                    if (await IsFlaskRunningAsync(apiUrl))
                    {
                        statusCallback?.Invoke($"Flask hazır ({i} sn)");
                        return true;
                    }
                }

                statusCallback?.Invoke("Flask başladı ama /health 15 sn'de cevap vermedi");
                return false;
            }
            catch (Exception ex)
            {
                statusCallback?.Invoke($"Flask başlatma hatası: {ex.Message}");
                Debug.WriteLine($"[FlaskLauncher] Exception: {ex}");
                return false;
            }
        }

        /// <summary>
        /// Çocuk process'i kapatır. Dışarıdan başlatılmış Flask'a dokunmaz.
        /// App kapanışında çağrılır.
        /// </summary>
        public static void Stop()
        {
            lock (_lock)
            {
                if (_flaskProcess == null) return;
                try
                {
                    if (!_flaskProcess.HasExited)
                    {
                        // entireProcessTree=true → Flask'ın açtığı alt thread'leri/process'leri de öldürür
                        _flaskProcess.Kill(entireProcessTree: true);
                        _flaskProcess.WaitForExit(2000);
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[FlaskLauncher] Stop hatası (göz ardı): {ex.Message}");
                }
                finally
                {
                    try { _flaskProcess.Dispose(); } catch { }
                    _flaskProcess = null;
                }
            }
        }

        private static async Task<bool> IsFlaskRunningAsync(string url)
        {
            try
            {
                var resp = await _healthClient.GetAsync($"{url.TrimEnd('/')}/health");
                return resp.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// PyInstaller ile derlenmiş predict.exe'yi arar. Bulunursa Python kurulumu gerekmez.
        /// Aynı sıra: exe dizini → kaynak ağacı → çalışma dizini.
        /// </summary>
        private static string? FindPredictExe()
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string[] candidates =
            {
                Path.Combine(baseDir, "predict.exe"),
                Path.Combine(baseDir, "..", "..", "..", "predict.exe"),
                Path.Combine(Directory.GetCurrentDirectory(), "predict.exe")
            };
            foreach (var c in candidates)
            {
                try
                {
                    string full = Path.GetFullPath(c);
                    if (File.Exists(full)) return full;
                }
                catch { }
            }
            return null;
        }

        /// <summary>
        /// predict.py'ı arar. Sıra:
        /// 1) App exe dizini (production build için CopyToOutputDirectory ile bırakılır)
        /// 2) ../../../ (Debug build için kaynak ağacındaki yer)
        /// 3) Process'in geçerli çalışma dizini
        /// </summary>
        private static string? FindPredictPy()
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string[] candidates =
            {
                Path.Combine(baseDir, "predict.py"),
                Path.Combine(baseDir, "..", "..", "..", "predict.py"),     // bin\Debug\netN → kaynak
                Path.Combine(Directory.GetCurrentDirectory(), "predict.py")
            };

            foreach (var c in candidates)
            {
                try
                {
                    string full = Path.GetFullPath(c);
                    if (File.Exists(full)) return full;
                }
                catch { /* path geçersizse atla */ }
            }
            return null;
        }

        /// <summary>Sistemde Python interpreter'ı arar.</summary>
        private static string? FindPythonExecutable()
        {
            foreach (var name in new[] { "py", "python", "python3" })
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = name,
                        Arguments = "--version",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };
                    using var p = Process.Start(psi);
                    if (p == null) continue;
                    p.WaitForExit(2000);
                    if (p.ExitCode == 0) return name;
                }
                catch { /* try next */ }
            }
            return null;
        }
    }
}
