# 🛡️ Siber Mail & Güvenlik Asistanı

Gmail tabanlı kurumsal kullanıcılar için **phishing, spam, SQL Injection, XSS ve Trojan
tespiti** yapan WPF (.NET 8) masaüstü uygulaması. Mail içeriklerini makine öğrenmesiyle,
URL ve dosyaları VirusTotal ile analiz eder; tehlikeli mailleri otomatik karantinaya alır.

> Bitirme Projesi · 2026

---

## ✨ Özellikler

- 📧 Gmail bağlantısı (IMAP/SMTP, MailKit)
- 🤖 Makine öğrenmesi ile phishing/spam tespiti (TF-IDF + scikit-learn)
- 🦠 VirusTotal entegrasyonu (URL & dosya hash, 70+ AV motoru)
- 🚨 Tehlikeli mailleri otomatik Çöp Kutusu'na taşıma
- 📦 Karantina yönetimi & PDF raporlama (QuestPDF)
- 🚫 Şüpheli gönderici listesi (manuel kara liste)
- 🔐 DPAPI ile parola şifreleme + KVKK uyumlu PII maskeleme
- 🌍 Türkçe / İngilizce dinamik dil desteği

---

## 🏗️ Mimari

```
┌─────────────────────────────────────────────┐
│         WPF UI (MainWindow.xaml)            │
└──────┬──────────────┬──────────────┬────────┘
       ▼              ▼              ▼
┌────────────┐ ┌────────────┐ ┌────────────────┐
│GmailService│ │VirusTotal  │ │ MLModelService │
│ (MailKit)  │ │  + Cache   │ │  → Flask API   │
└─────┬──────┘ └─────┬──────┘ └────────┬───────┘
      │              │                  │
      ▼              ▼                  ▼
┌──────────────────────────┐   ┌──────────────────┐
│   SQLite (siberkalkan.db)│   │  predict.exe     │
│   + DPAPI şifreleme      │   │ (PyInstaller)    │
│   + PII maskeleme        │   │ scikit-learn ML  │
└──────────────────────────┘   └──────────────────┘
```

---

## 🧰 Teknoloji Stack

| Katman | Teknoloji |
|--------|-----------|
| UI | WPF + XAML (.NET 8) |
| Mail | MailKit 4.3, MimeKit 4.3 |
| Veritabanı | SQLite (Microsoft.Data.Sqlite 8.0) |
| ML | Python 3.10+ · Flask · scikit-learn (TF-IDF) |
| PDF | QuestPDF 2026.2 |
| Güvenlik | DPAPI (Windows Data Protection API) |
| Dış API | VirusTotal Public API v3 |

---

## 💻 Sistem Gereksinimleri

- Windows 10/11 (x64)
- .NET 8.0 Runtime
- 4 GB RAM (önerilen 8 GB)
- İnternet bağlantısı
- **Python kurulumuna gerek YOK** — `predict.exe` bundle dahildir

---

## 🚀 Kurulum

### Geliştirici Kurulumu

```bash
git clone https://github.com/<KULLANICI>/CyberSecurityAssistant.git
cd CyberSecurityAssistant
dotnet restore
dotnet build
dotnet run
```

> Uygulama açılırken Flask servisi (`predict.exe`) otomatik başlatılır.
> İlk açılışta **KVKK aydınlatma metni** ekranı çıkar.

### Yapılandırma — `appsettings.json`

```json
{
  "InternalApiAuthToken": "SiberSahin-Auth-Token",
  "FlaskApiUrl": "http://localhost:5000",
  "VirusTotalCacheHours": 24,
  "DefaultLanguage": "TR"
}
```

---

## 📬 Gmail Bağlantısı

Gmail normal şifre kabul etmez — **App Password** gerekir:

1. https://myaccount.google.com/security → 2 Adımlı Doğrulamayı aktifleştir
2. https://myaccount.google.com/apppasswords → "Siber Mail Güvenlik" adıyla oluştur
3. 16 karakterlik kodu kopyala
4. Uygulamada: **⚙️ Ayarlar → Gmail Hesabı** → e-posta + App Password → **Bağlan**

> Parolanız DPAPI ile şifrelenir, yalnızca aynı Windows kullanıcısı çözebilir.

---

## 🔐 VirusTotal API

1. https://www.virustotal.com/gui/join-us → Kayıt ol
2. Profil → **API Key** kopyala
3. Uygulamada: **⚙️ Ayarlar → VirusTotal API** → yapıştır → **Kaydet**

> Ücretsiz limit: 4 istek/dakika. 24 saatlik lokal cache ile aynı URL tekrar sorulmaz.

---

## 📖 Kullanım

| İşlem | Nereden |
|-------|---------|
| Mail listesi | Sol panelden klasör seç (Inbox / Spam / Trash...) |
| Mail detayı + skor | Mail'e tıkla → sağ panel |
| URL/dosya manuel tarama | **🔍 Tarama** paneli |
| Otomatik senkronizasyon | **⚙️ Ayarlar → Senkronizasyon Aralığı** (1-30 dk) |
| Şüpheli gönderici ekle | **🚫 Şüpheli Göndericiler** paneli |
| Karantina | **📦 Karantina** paneli |
| PDF rapor | **📊 Raporlar → PDF Oluştur** |
| Dil değiştir | **⚙️ Ayarlar → Dil (TR/EN)** |

**Tehdit rozetleri:** 🔴 Phishing · 🟠 Spam · 🟣 SQL Injection · 🩷 XSS · 🟦 Trojan

---

## 🗄️ Veritabanı Şeması

SQLite (`siberkalkan.db`) — ilk açılışta otomatik oluşur.

| Tablo | Amaç |
|-------|------|
| `mailler` | Tüm mailler + tehdit skorları |
| `klasorler` | Mail klasörleri |
| `analiz_loglari` | Her analizin kaydı (PII maskeli) |
| `zararli_linkler` / `ekli_dosyalar` | Karantina kayıtları |
| `gmail_hesaplari` | DPAPI ile şifrelenmiş App Password |
| `supheli_gondericiler` | Kullanıcı kara listesi |
| `vt_cache` | VirusTotal 24h cache |
| `sistem_loglari` / `ayarlar` | Sistem olayları & yapılandırma |

Performans için indeksler: `gmail_mesaj_id`, `(klasor_id, tarih DESC)`, `log_id` (JOIN'ler).

---

## 🇹🇷 KVKK Uyumluluğu

İlk açılışta gösterilen **KVKK Aydınlatma Metni** + veritabanı loglarında otomatik PII
maskeleme:

| Veri Tipi | Maskeli Hâli |
|-----------|--------------|
| E-posta | `[E-POSTA GİZLENDİ]` |
| TC Kimlik No (11 hane) | `[TC KİMLİK GİZLENDİ]` |
| Telefon (TR) | `[TELEFON GİZLENDİ]` |
| Kredi Kartı (16 hane) | `[KART GİZLENDİ]` |
| IBAN (TR + 24 hane) | `[IBAN GİZLENDİ]` |
| CVV | `[CVV GİZLENDİ]` |

---

## 📁 Proje Yapısı

```
CyberSecurityAssistant/
├── App.xaml(.cs)              # Single Instance Mutex
├── MainWindow.xaml(.cs)       # Ana UI
├── appsettings.json           # Yapılandırma
├── predict.py / predict.exe   # Flask ML servisi
├── Models/                    # ML model dosyaları (.pkl)
├── Languages/                 # TR / EN dil kaynakları
└── Services/
    ├── DatabaseHelper.cs      # SQLite + PII mask
    ├── GmailService.cs        # IMAP/SMTP
    ├── VirusTotalService.cs   # VT API v3 client
    ├── VtCache.cs             # 24h TTL cache
    ├── MLModelService.cs      # Flask client
    ├── FlaskServiceLauncher.cs # predict.exe spawn
    ├── SecureStore.cs         # DPAPI
    └── AppConfig.cs           # appsettings.json reader
```

---

## 📚 Önlisans

Akademik bitirme projesi · 2026
