using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using MahApps.Metro.IconPacks;
using Color = System.Windows.Media.Color;
using ColorConverter = System.Windows.Media.ColorConverter;
using Brushes = System.Windows.Media.Brushes;
using DragEventArgs = System.Windows.DragEventArgs;
using DataFormats = System.Windows.DataFormats;
using MessageBox = System.Windows.MessageBox;
using Application = System.Windows.Application;
using Colors = QuestPDF.Helpers.Colors;
using Fonts = QuestPDF.Helpers.Fonts;

namespace CyberSecurityAssistant
{
    public partial class MainWindow : Window
    {
        // ==========================================
        // DİNAMİK API AYARLARI
        // ==========================================
        private string _apiKey = "";
        private readonly string _settingsFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "vt_apikey.txt");
        private static readonly HttpClient _httpClient = new HttpClient();

        // SİSTEM TEPSİSİ (SYSTEM TRAY) İKONU 
        private System.Windows.Forms.NotifyIcon _notifyIcon = new System.Windows.Forms.NotifyIcon();
        private FileSystemWatcher _folderWatcher = null!;

        public MainWindow()
        {
            InitializeComponent();
            LoadApiKey();
            SetupSystemTray();
            SetupFolderWatcher();
            QuestPDF.Settings.License = QuestPDF.Infrastructure.LicenseType.Community;
        }

        // ==========================================
        // --- SİSTEM TEPSİSİ (ARKA PLAN) İŞLEMLERİ ---
        // ==========================================
        private void SetupSystemTray()
        {
            _notifyIcon.Icon = System.Drawing.SystemIcons.Shield;
            _notifyIcon.Visible = true;
            _notifyIcon.Text = Application.Current.FindResource("MsgTrayIconHover").ToString();

            _notifyIcon.DoubleClick += (s, e) => ShowMainWindow();

            var contextMenu = new System.Windows.Forms.ContextMenuStrip();

            var openItem = contextMenu.Items.Add(Application.Current.FindResource("MsgTrayOpenUI").ToString());
            openItem.Click += (s, e) => ShowMainWindow();

            contextMenu.Items.Add(new System.Windows.Forms.ToolStripSeparator());

            var closeItem = contextMenu.Items.Add(Application.Current.FindResource("MsgTrayExit").ToString());
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

            Environment.Exit(0);
        }

        // ==========================================
        // --- AYARLAR MENÜSÜ İŞLEMLERİ ---
        // ==========================================
        private void LoadApiKey()
        {
            if (File.Exists(_settingsFilePath))
            {
                _apiKey = File.ReadAllText(_settingsFilePath).Trim();
                UpdateApiStatusUI();
            }
        }

        private void OpenSettings_Click(object sender, RoutedEventArgs e)
        {
            SettingsOverlay.Visibility = Visibility.Visible;
        }

        private void CloseSettings_Click(object sender, RoutedEventArgs e)
        {
            SettingsOverlay.Visibility = Visibility.Collapsed;
        }

        private void SaveSettings_Click(object sender, RoutedEventArgs e)
        {
            File.WriteAllText(_settingsFilePath, _apiKey);
            SettingsOverlay.Visibility = Visibility.Collapsed;
            UpdateApiStatusUI();
        }

        private void UpdateApiStatusUI()
        {
            if (string.IsNullOrEmpty(_apiKey))
            {
                ApiStatusIcon.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
                ApiStatusText.Text = Application.Current.FindResource("MsgApiWaiting").ToString();
                ApiStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
            }
            else
            {
                ApiStatusIcon.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#22C55E"));
                ApiStatusText.Text = Application.Current.FindResource("MsgApiConnected").ToString();
                ApiStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4ADE80"));
            }
        }

        // ==========================================
        // --- SEKME VE DOSYA İŞLEMLERİ ---
        // ==========================================
        private void TabMetin_Click(object sender, RoutedEventArgs e)
        {
            SetActiveTabState(TabMetin);
            PanelText.Visibility = Visibility.Visible;
            PanelUrl.Visibility = Visibility.Collapsed;
            PanelDosya.Visibility = Visibility.Collapsed;
        }

        private void TabUrl_Click(object sender, RoutedEventArgs e)
        {
            SetActiveTabState(TabUrl);
            PanelText.Visibility = Visibility.Collapsed;
            PanelUrl.Visibility = Visibility.Visible;
            PanelDosya.Visibility = Visibility.Collapsed;
        }

        private void TabDosya_Click(object sender, RoutedEventArgs e)
        {
            SetActiveTabState(TabDosya);
            PanelText.Visibility = Visibility.Collapsed;
            PanelUrl.Visibility = Visibility.Collapsed;
            PanelDosya.Visibility = Visibility.Visible;
        }

        private void SetActiveTabState(System.Windows.Controls.Button activeTab)
        {
            var inactiveColor = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#A0A0A0"));

            TabMetin.Background = Brushes.Transparent;
            TabMetin.Foreground = inactiveColor;

            TabUrl.Background = Brushes.Transparent;
            TabUrl.Foreground = inactiveColor;

            TabDosya.Background = Brushes.Transparent;
            TabDosya.Foreground = inactiveColor;

            activeTab.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#333333"));
            activeTab.Foreground = Brushes.White;
        }

        private string _selectedFilePath = "";

        private void BrowseFile_Click(object sender, RoutedEventArgs e)
        {
            Microsoft.Win32.OpenFileDialog openFileDialog = new Microsoft.Win32.OpenFileDialog();
            openFileDialog.Title = Application.Current.FindResource("MsgFileDialogTitle").ToString();
            openFileDialog.Filter = Application.Current.FindResource("MsgFileDialogFilter").ToString();

            if (openFileDialog.ShowDialog() == true)
            {
                _selectedFilePath = openFileDialog.FileName;
                SelectedFileNameText.Text = "Seçilen Dosya: " + openFileDialog.SafeFileName;
                SelectedFileNameText.Foreground = Brushes.White;
            }
        }

        private void PanelDosya_Drop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files != null && files.Length > 0)
                {
                    _selectedFilePath = files[0];
                    SelectedFileNameText.Text = "Seçilen Dosya: " + Path.GetFileName(_selectedFilePath);
                    SelectedFileNameText.Foreground = Brushes.White;
                }
            }
        }

        // ==========================================
        // --- METİN (PHISHING) ANALİZİ ---
        // ==========================================
        private (int score, string details) AnalyzeTextForPhishing(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return (0, "Metin bulunamadı.");

            text = text.ToLowerInvariant();
            int score = 0;
            string details = "";

            string[] urgencyWords = { "acil", "hemen", "son uyarı", "kapatılacak", "askıya", "24 saat", "iptal edilecek", "zorunlu" };
            foreach (var word in urgencyWords)
            {
                if (text.Contains(word))
                {
                    score += 35;
                    details += "• Aciliyet/Tehdit taktiği algılandı.\n";
                    break;
                }
            }

            string[] infoWords = { "şifre", "parola", "kredi kartı", "tc kimlik", "hesap doğrula", "ödeme yap", "kripto", "iban" };
            foreach (var word in infoWords)
            {
                if (text.Contains(word))
                {
                    score += 45;
                    details += "• Hassas bilgi veya para talebi algılandı.\n";
                    break;
                }
            }

            string[] actionWords = { "buraya tıkla", "linke tıkla", "ekteki dosya", "faturayı incele", "giriş yap", "indirmek için" };
            foreach (var word in actionWords)
            {
                if (text.Contains(word))
                {
                    score += 20;
                    details += "• Şüpheli eylem/link yönlendirmesi algılandı.\n";
                    break;
                }
            }

            if (text.Contains("değerli müşterimiz") || text.Contains("sayın kullanıcı") || text.Contains("sayın abonemiz"))
            {
                score += 10;
                details += "• Şüpheli genel hitap (Phishing taktiği).\n";
            }

            if (score > 100) score = 100;
            if (score == 0) details = "Herhangi bir oltalama (phishing) taktiği tespit edilmedi.";

            return (score, details.TrimEnd());
        }

        // ==========================================
        // --- TARAMA VE SİLME İŞLEMLERİ ---
        // ==========================================
        private async void Scan_button_Click(object sender, RoutedEventArgs e)
        {
            string apiTitle = Application.Current.FindResource("MsgMissingApiTitle").ToString();
            string apiDesc = Application.Current.FindResource("MsgMissingApiDesc").ToString();

            if (PanelText.Visibility != Visibility.Visible && string.IsNullOrEmpty(_apiKey))
            {
                SetResultUI(apiTitle, apiDesc, false, true);
                return;
            }

            ResetButton.Visibility = Visibility.Hidden;
            DeleteThreatButton.Visibility = Visibility.Collapsed;

            ShieldIcon.Kind = PackIconMaterialKind.CogOutline;
            ShieldIcon.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FBBF24"));
            ShieldGlow.Color = (Color)ColorConverter.ConvertFromString("#FBBF24");
            StatusText.Text = Application.Current.FindResource("MsgProcessing").ToString();
            StatusText.Foreground = Brushes.Yellow;
            ScanDescriptionText.Text = Application.Current.FindResource("MsgPleaseWait").ToString();

            ScanProgressBar.Visibility = Visibility.Visible;
            ScanProgressBar.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FBBF24"));
            DoubleAnimation progressAnim = new DoubleAnimation(0, 80, TimeSpan.FromSeconds(2));
            ScanProgressBar.BeginAnimation(System.Windows.Controls.Primitives.RangeBase.ValueProperty, progressAnim);

            var storyboard = (Storyboard)FindResource("PulseAnimation");
            storyboard.Begin();

            if (PanelText.Visibility == Visibility.Visible)
            {
                AiStatusIcon.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FBBF24"));
                AiStatusText.Text = Application.Current.FindResource("MsgNlpAnalysis").ToString();
                AiStatusText.Foreground = Brushes.Yellow;
            }
            else
            {
                ApiStatusIcon.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FBBF24"));
                ApiStatusText.Text = Application.Current.FindResource("MsgVtConnecting").ToString();
                ApiStatusText.Foreground = Brushes.Yellow;
            }

            try
            {
                int malicious = 0;
                int total = 0;
                bool isScanned = false;

                string statusText = Application.Current.FindResource("SafeContentText").ToString();
                string title = Application.Current.FindResource("MsgInvalidTitle").ToString();
                string desc = Application.Current.FindResource("MsgInvalidDesc").ToString();
                string formatScoreDesc = Application.Current.FindResource("MsgThreatScoreDetails").ToString();

                if (PanelDosya.Visibility == Visibility.Visible && !string.IsNullOrEmpty(_selectedFilePath))
                {
                    string fileHash = ComputeSha256(_selectedFilePath);
                    var result = await CheckVirusTotalAsync($"files/{fileHash}");
                    malicious = result.maliciousCount;
                    total = result.totalEngines;
                    isScanned = true;
                }
                else if (PanelUrl.Visibility == Visibility.Visible && InputUrl.Text.Length > 8)
                {
                    string urlBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(InputUrl.Text))
                                              .Replace("+", "-").Replace("/", "_").TrimEnd('=');
                    var result = await CheckVirusTotalAsync($"urls/{urlBase64}");
                    malicious = result.maliciousCount;
                    total = result.totalEngines;
                    isScanned = true;
                }
                else if (PanelText.Visibility == Visibility.Visible && InputText.Text.Length > 10)
                {
                    await Task.Delay(1500);
                    var (score, details) = AnalyzeTextForPhishing(InputText.Text);

                    if (score >= 70)
                    {
                        string titlePhising = Application.Current.FindResource("MsgPhishingTitle").ToString();
                        string formatCriRisk = Application.Current.FindResource("MsgCriticalPhishingRisk").ToString();
                        SetResultUI(titlePhising, string.Format(formatScoreDesc, score, details), true);

                        AiStatusIcon.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
                        AiStatusText.Text = string.Format(formatCriRisk, score);
                        AiStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
                    }
                    else if (score >= 30)
                    {
                        string titleSuspicious = Application.Current.FindResource("MsgSuspiciousTextTitle").ToString();
                        string formatWarnRisk = Application.Current.FindResource("MsgWarningSuspiciousContent").ToString();

                        SetResultUI(titleSuspicious, string.Format(formatScoreDesc, score, details), false, true);
                        AiStatusIcon.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));
                        AiStatusText.Text = string.Format(formatWarnRisk, score);
                        AiStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FBBF24"));
                    }
                    else
                    {
                        SetResultUI(statusText, string.Format(formatScoreDesc, score, details), false);
                        AiStatusIcon.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#22C55E"));
                        AiStatusText.Text = Application.Current.FindResource("MsgAnalysisClean").ToString();
                        AiStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4ADE80"));
                    }
                    isScanned = true;
                }

                if (isScanned && PanelText.Visibility != Visibility.Visible)
                {
                    if (malicious > 0)
                    {
                        string titleThreatVt = Application.Current.FindResource("MsgVtThreatFoundTitle").ToString();
                        string formatApiThreat = Application.Current.FindResource("MsgApiThreatFound").ToString();
                        string vtThreatMessage = string.Format(formatApiThreat, malicious);

                        SetResultUI(titleThreatVt, vtThreatMessage, true);

                        ApiStatusIcon.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
                        ApiStatusText.Text = string.Format(formatApiThreat, malicious);
                        ApiStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));

                        if (PanelDosya.Visibility == Visibility.Visible && !string.IsNullOrEmpty(_selectedFilePath))
                        {
                            DeleteThreatButton.Visibility = Visibility.Visible;
                        }
                    }
                    else if (total > 0)
                    {
                        string titleSafe = Application.Current.FindResource("MsgSafeContentTitle").ToString();
                        string formatSafeDesc = Application.Current.FindResource("MsgSafeContentDesc").ToString();
                        string apiClean = Application.Current.FindResource("MsgApiClean").ToString();

                        SetResultUI(titleSafe, string.Format(formatSafeDesc, total), false);
                        ApiStatusIcon.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#22C55E"));
                        ApiStatusText.Text = apiClean;
                        ApiStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4ADE80"));
                    }
                    else
                    {
                        string titleUnknown = Application.Current.FindResource("MsgUnknownTitle").ToString();
                        string descUnknown = Application.Current.FindResource("MsgUnknownDesc").ToString();
                        string apiUnknown = Application.Current.FindResource("MsgApiUnknown").ToString();

                        SetResultUI(titleUnknown, descUnknown, false, true);
                        ApiStatusIcon.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));
                        ApiStatusText.Text = apiUnknown;
                        ApiStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FBBF24"));
                    }
                }
                else if (!isScanned)
                {
                    await Task.Delay(1000);
                    SetResultUI(title, desc, false, true);
                }
            }
            catch (Exception)
            {
                string errorTitle = Application.Current.FindResource("MsgConnectionErrorTitle").ToString();
                string errorDesc = Application.Current.FindResource("MsgConnectionErrorDesc").ToString();
                string errorApi = Application.Current.FindResource("MsgApiConnectionLost").ToString();

                SetResultUI(errorTitle, errorDesc, false, true);
                ApiStatusIcon.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
                ApiStatusText.Text = errorApi;
                ApiStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
            }

            storyboard.Stop();
            ScanProgressBar.BeginAnimation(System.Windows.Controls.Primitives.RangeBase.ValueProperty, null);
            ScanProgressBar.Value = 100;
            PdfReportButton.Visibility = Visibility.Visible;
            ResetButton.Visibility = Visibility.Visible;
        }

        private void DeleteThreat_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (File.Exists(_selectedFilePath))
                {
                    string titleDeleted = Application.Current.FindResource("MsgThreatDeletedTitle").ToString();
                    string DescDeleted = Application.Current.FindResource("MsgThreatDeletedDesc").ToString();

                    File.Delete(_selectedFilePath);
                    SetResultUI(titleDeleted, DescDeleted, false);
                    DeleteThreatButton.Visibility = Visibility.Collapsed;
                    SelectedFileNameText.Text = Application.Current.FindResource("SelectedFileNameText").ToString();
                    SelectedFileNameText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#A0A0A0"));
                    _selectedFilePath = "";
                }
            }
            catch (Exception ex)
            {
                string titleDeleteError = Application.Current.FindResource("MsgDeleteFailedTitle").ToString();
                string formatDeleteError = Application.Current.FindResource("MsgDeleteFailedDesc").ToString();

                string errorMessage = string.Format(formatDeleteError, ex.Message);

                MessageBox.Show(errorMessage, titleDeleteError, MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SetResultUI(string title, string desc, bool isDanger, bool isWarning = false)
        {
            if (isDanger)
            {
                ShieldIcon.Kind = PackIconMaterialKind.ShieldAlertOutline;
                ShieldIcon.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
                ShieldGlow.Color = (Color)ColorConverter.ConvertFromString("#EF4444");
                StatusText.Text = title;
                StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
                ScanProgressBar.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
            }
            else if (isWarning)
            {
                ShieldIcon.Kind = PackIconMaterialKind.AlertOutline;
                ShieldIcon.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));
                ShieldGlow.Color = (Color)ColorConverter.ConvertFromString("#F59E0B");
                StatusText.Text = title;
                StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FBBF24"));
                ScanProgressBar.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));
            }
            else
            {
                ShieldIcon.Kind = PackIconMaterialKind.ShieldCheckOutline;
                ShieldIcon.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#22C55E"));
                ShieldGlow.Color = (Color)ColorConverter.ConvertFromString("#22C55E");
                StatusText.Text = title;
                StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4ADE80"));
                ScanProgressBar.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#22C55E"));
            }

            ScanDescriptionText.Text = desc;
        }

        private string ComputeSha256(string filePath)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                using (FileStream fileStream = File.OpenRead(filePath))
                {
                    byte[] hashBytes = sha256.ComputeHash(fileStream);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                }
            }
        }

        private async Task<(int maliciousCount, int totalEngines)> CheckVirusTotalAsync(string endpointUrl)
        {
            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("x-apikey", _apiKey);

            HttpResponseMessage response = await _httpClient.GetAsync($"https://www.virustotal.com/api/v3/{endpointUrl}");

            if (response.IsSuccessStatusCode)
            {
                string jsonResponse = await response.Content.ReadAsStringAsync();
                using (JsonDocument doc = JsonDocument.Parse(jsonResponse))
                {
                    var stats = doc.RootElement.GetProperty("data").GetProperty("attributes").GetProperty("last_analysis_stats");
                    int malicious = stats.GetProperty("malicious").GetInt32();
                    int harmless = stats.GetProperty("harmless").GetInt32();
                    int undetected = stats.GetProperty("undetected").GetInt32();
                    int suspicious = stats.GetProperty("suspicious").GetInt32();

                    int total = malicious + harmless + undetected + suspicious;
                    return (malicious + suspicious, total);
                }
            }
            else if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return (0, 0);
            }

            string apiErrorMessage = Application.Current.FindResource("MsgApiErrorException").ToString();
            throw new Exception(apiErrorMessage);
        }

        private void Reset_button_Click(object sender, RoutedEventArgs e)
        {
            string titleSafe = Application.Current.FindResource("MsgSafeContentTitle").ToString();
            string descAi = Application.Current.FindResource("MsgAiSafeContentDesc").ToString();

            SetResultUI(titleSafe, descAi, false);
            ScanProgressBar.Visibility = Visibility.Collapsed;
            ScanProgressBar.Value = 0;

            if (InputText != null) InputText.Text = "";
            if (InputUrl != null) InputUrl.Text = "";

            SelectedFileNameText.Text = Application.Current.FindResource("SelectedFileNameText").ToString();
            SelectedFileNameText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#A0A0A0"));
            _selectedFilePath = "";

            PdfReportButton.Visibility = Visibility.Collapsed;
            ResetButton.Visibility = Visibility.Hidden;
            DeleteThreatButton.Visibility = Visibility.Collapsed;

            AiStatusIcon.Foreground = Brushes.White;
            AiStatusText.Text = Application.Current.FindResource("MsgAiAccuracy").ToString();
            AiStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#A0A0A0"));
            UpdateApiStatusUI();
        }

        // ==========================================
        // --- PENCERE KONTROLLERİ VE TRAY ---
        // ==========================================
        private void Window_MouseDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (e.ChangedButton == System.Windows.Input.MouseButton.Left) this.DragMove();
        }

        private void Maximize_Click(object sender, RoutedEventArgs e)
        {
            if (this.WindowState == WindowState.Normal)
            {
                IntPtr handle = new System.Windows.Interop.WindowInteropHelper(this).Handle;
                var ekran = System.Windows.Forms.Screen.FromHandle(handle);

                this.MaxWidth = ekran.WorkingArea.Width;
                this.MaxHeight = ekran.WorkingArea.Height;

                this.WindowState = WindowState.Maximized;

                MaximizeIcon.Kind = PackIconMaterialKind.WindowRestore;
            }
            else
            {
                this.MaxWidth = double.PositiveInfinity;
                this.MaxHeight = double.PositiveInfinity;
                this.WindowState = WindowState.Normal;

                MaximizeIcon.Kind = PackIconMaterialKind.WindowMaximize;
            }
        }

        private void Minimize_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
        }

        // ==========================================
        // --- PDF RAPORU OLUŞTURMA İŞLEMİ ---
        // ==========================================
        private void PdfReport_Click(object sender, RoutedEventArgs e)
        {
            Microsoft.Win32.SaveFileDialog saveFileDialog = new Microsoft.Win32.SaveFileDialog();
            saveFileDialog.Filter = "PDF Dosyası (*.pdf)|*.pdf";
            saveFileDialog.Title = "Güvenlik Raporunu Kaydet";
            saveFileDialog.FileName = "Siber_Tarama_Raporu_" + DateTime.Now.ToString("yyyyMMdd_HHmm") + ".pdf";

            if (saveFileDialog.ShowDialog() == true)
            {
                try
                {
                    Document.Create(container =>
                    {
                        container.Page(page =>
                        {
                            page.Size(PageSizes.A4);
                            page.Margin(2, Unit.Centimetre);
                            page.PageColor(Colors.White);
                            page.DefaultTextStyle(x => x.FontSize(12).FontFamily(Fonts.Arial));

                            page.Header().Text("SiberAsistanı - Güvenlik Analiz Raporu").SemiBold().FontSize(22).FontColor(Colors.Blue.Darken2);

                            page.Content().PaddingVertical(1, Unit.Centimetre).Column(x =>
                            {
                                x.Spacing(15);

                                x.Item().Text($"Tarama Tarihi: {DateTime.Now:dd.MM.yyyy HH:mm}").FontSize(10).FontColor(Colors.Grey.Medium);
                                x.Item().LineHorizontal(1).LineColor(Colors.Grey.Lighten2);

                                string targetType = "";
                                string targetData = "";

                                if (PanelDosya.Visibility == Visibility.Visible)
                                {
                                    targetType = "Dosya Analizi";
                                    targetData = _selectedFilePath;
                                }
                                else if (PanelUrl.Visibility == Visibility.Visible)
                                {
                                    targetType = "Bağlantı (URL) Analizi";
                                    targetData = InputUrl.Text;
                                }
                                else
                                {
                                    targetType = "Metin (Phishing) Analizi";
                                    targetData = InputText.Text;
                                }

                                x.Item().Text("Hedef Türü: " + targetType).SemiBold().FontSize(14);
                                x.Item().Background(Colors.Grey.Lighten4).Padding(10).Text(targetData).Italic();

                                x.Item().PaddingTop(10).Text("Analiz Sonucu:").SemiBold().FontSize(14);

                                string status = StatusText.Text;
                                string desc = ScanDescriptionText.Text;

                                string resultColor = status.Contains("TEHDİT") || status.Contains("OLTALAMA")
                                    ? Colors.Red.Medium
                                    : (status.Contains("ŞÜPHELİ") || status.Contains("BİLİNMEYEN")
                                        ? Colors.Orange.Medium
                                        : Colors.Green.Medium);

                                x.Item().Text(status).FontSize(18).Bold().FontColor(resultColor);
                                x.Item().Text(desc).FontSize(12);

                                x.Item().PaddingTop(20).LineHorizontal(1).LineColor(Colors.Grey.Lighten2);
                                x.Item().Text("Bu rapor, yapay zeka ve VirusTotal motorları kullanılarak otomatik oluşturulmuştur.").FontSize(9).FontColor(Colors.Grey.Medium).Italic();
                            });

                            page.Footer().AlignCenter().Text(x =>
                            {
                                x.Span("Sayfa ");
                                x.CurrentPageNumber();
                                x.Span(" / ");
                                x.TotalPages();
                            });
                        });
                    })
                    .GeneratePdf(saveFileDialog.FileName);

                    MessageBox.Show("Rapor başarıyla kaydedildi!\n\n" + saveFileDialog.FileName, "İşlem Başarılı", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("PDF oluşturulurken bir hata oluştu: " + ex.Message, "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        // ==========================================
        // --- GERÇEK ZAMANLI KLASÖR DİNLEME MOTORU ---
        // ==========================================
        private void SetupFolderWatcher()
        {
            string downloadsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

            _folderWatcher = new FileSystemWatcher(downloadsPath);
            _folderWatcher.NotifyFilter = NotifyFilters.FileName;
            _folderWatcher.Filter = "*.*";

            _folderWatcher.Created += OnFileDetected;
            _folderWatcher.Renamed += OnFileDetected;
        }

        private void AutoScan_Click(object sender, RoutedEventArgs e)
        {
            if (AutoScanCheckBox.IsChecked == true)
            {
                string radarTitle = Application.Current.FindResource("MsgRadarActiveTitle").ToString();
                string radarDesc = Application.Current.FindResource("MsgRadarActiveDesc").ToString();

                _folderWatcher.EnableRaisingEvents = true;
                _notifyIcon.ShowBalloonTip(2000, radarTitle, radarDesc, System.Windows.Forms.ToolTipIcon.Info);
            }
            else
            {
                _folderWatcher.EnableRaisingEvents = false;
            }
        }

        private async void OnFileDetected(object sender, FileSystemEventArgs e)
        {
            string dosyaUzantisi = Path.GetExtension(e.FullPath).ToLower();

            if (dosyaUzantisi == ".crdownload" || dosyaUzantisi == ".tmp" || dosyaUzantisi == ".part")
                return;

            await Task.Delay(1500);

            Application.Current.Dispatcher.Invoke(() =>
            {
                if (this.Visibility != Visibility.Visible || this.WindowState == WindowState.Minimized)
                {
                    this.Show();
                    this.WindowState = WindowState.Normal;
                    this.Activate();
                }

                TabDosya_Click(this, new RoutedEventArgs());

                string formatAutoDetect = Application.Current.FindResource("MsgAutoCaught").ToString();
                string radarNewTitle = Application.Current.FindResource("MsgNewFileCaughtTitle").ToString();
                string formatRadarNewDesc = Application.Current.FindResource("MsgNewFileCaughtDesc").ToString();

                _selectedFilePath = e.FullPath;
                SelectedFileNameText.Text = string.Format(formatAutoDetect, e.Name);
                SelectedFileNameText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3B82F6")); // Mavi vurgu

                string radarNewDesc = string.Format(formatRadarNewDesc, e.Name);
                _notifyIcon.ShowBalloonTip(3000, radarNewTitle, radarNewDesc, System.Windows.Forms.ToolTipIcon.Warning);

                Scan_button_Click(this, new RoutedEventArgs());
            });
        }

        private bool _isApiVisible = false;

        private void ToggleApiVisibility_Click(object sender, RoutedEventArgs e)
        {
            _isApiVisible = !_isApiVisible;

            if (_isApiVisible)
            {
                ApiTextBox.Text = ApiPasswordBox.Password;
                ApiPasswordBox.Visibility = Visibility.Collapsed;
                ApiTextBox.Visibility = Visibility.Visible;
                ToggleEyeIcon.Kind = PackIconMaterialKind.EyeOffOutline;
            }
            else
            {
                ApiPasswordBox.Password = ApiTextBox.Text;
                ApiTextBox.Visibility = Visibility.Collapsed;
                ApiPasswordBox.Visibility = Visibility.Visible;
                ToggleEyeIcon.Kind = PackIconMaterialKind.EyeOutline;
            }
        }

        private void ApiPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            if (!_isApiVisible)
            {
                _apiKey = ApiPasswordBox.Password;
            }
        }

        private void ApiTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (_isApiVisible)
            {
                _apiKey = ApiTextBox.Text;
            }
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            string shieldTitle = Application.Current.FindResource("MsgShieldActiveTitle").ToString();
            string shieldDesc = Application.Current.FindResource("MsgShieldActiveDesc").ToString();

            this.Hide();
            _notifyIcon.ShowBalloonTip(2000, shieldTitle, shieldDesc, System.Windows.Forms.ToolTipIcon.Info);
        }

        // ==========================================
        // --- ÇOKLU DİL (MULTILANGUAGE) MOTORU ---
        // ==========================================

        private void ChangeLanguage(String languageCode)
        {
            ResourceDictionary dict = new ResourceDictionary();

            switch (languageCode)
            {
                case "EN":
                    dict.Source = new Uri("..\\Languages\\StringResources.en.xaml", UriKind.Relative);
                    break;
                default:
                    dict.Source = new Uri("..\\Languages\\StringResources.tr.xaml", UriKind.Relative);
                    break;
            }

            Application.Current.Resources.MergedDictionaries.Clear();
            Application.Current.Resources.MergedDictionaries.Add(dict);
        }

        private void LangTR_Click(object sender, RoutedEventArgs e) => ChangeLanguage("TR");
        private void LangEN_Click(object sender, RoutedEventArgs e) => ChangeLanguage("EN");
    }
}