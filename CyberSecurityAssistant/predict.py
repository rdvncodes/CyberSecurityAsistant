import os
import sys
import re
import pickle
import json
import time
import threading
from datetime import datetime
from flask import Flask, request, jsonify
from imap_tools import MailBox, AND, MailMessageFlags
import sqlite3

# Windows PowerShell default encoding'i (cp1254) Unicode karakterleri yazamaz.
# UTF-8'e zorla — okları, Türkçe karakterleri, emojileri sorunsuz yazar.
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

app = Flask(__name__)

# PyInstaller --onefile ile derlenirse __file__ TEMP'te _MEIxxx içine açılır.
# sys.executable EXE'nin gerçek konumunu verir — Models ve DB onun yanında olur.
# Normal Python ile çalıştırılırsa __file__ kullanılır.
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# appsettings.json'dan token oku — hardcoded olmasın
INTERNAL_AUTH_TOKEN = "SiberSahin-Auth-Token"  # default fallback
try:
    _cfg_path = os.path.join(BASE_DIR, "appsettings.json")
    if os.path.exists(_cfg_path):
        with open(_cfg_path, "r", encoding="utf-8") as f:
            _cfg = json.load(f)
            INTERNAL_AUTH_TOKEN = _cfg.get("InternalApiAuthToken", INTERNAL_AUTH_TOKEN)
except Exception as _e:
    print(f"[Config] appsettings.json okunamadı, varsayılan token kullanılıyor: {_e}")

MODELS_PATH = os.path.join(BASE_DIR, "Models")
# DB normalde C# uygulamasının yanındadır. Frozen modda exe yanında, normal modda
# bin/Debug yapısı altında (geliştirici testi için).
if getattr(sys, "frozen", False):
    DB_PATH = os.path.join(BASE_DIR, "siberkalkan.db")
else:
    DB_PATH = os.path.join(BASE_DIR, "bin", "Debug", "net8.0-windows", "siberkalkan.db")

phishing_model = None
spam_model = None
vectorizer = None
gmail_account = None


# ── Model loading (accepts both legacy and new filenames) ────────────────────

def load_models():
    global phishing_model, spam_model, vectorizer

    phishing_paths   = [os.path.join(MODELS_PATH, "phishing_model.pkl"), os.path.join(MODELS_PATH, "mail_model.pkl")]
    spam_paths       = [os.path.join(MODELS_PATH, "spam_model.pkl"),     os.path.join(MODELS_PATH, "mail_model.pkl")]
    vectorizer_paths = [os.path.join(MODELS_PATH, "vectorizer.pkl"),     os.path.join(MODELS_PATH, "tfidf_vectorizer.pkl")]

    def _try_load(paths, label):
        """Tek bir model dosyasını güvenli şekilde yüklemeyi dener.
        Pickle bozuksa, sklearn versiyonu uyumsuzsa veya başka bir hata olursa
        None döner — Flask çökmeden heuristik moda geçer."""
        for path in paths:
            if not os.path.exists(path):
                continue
            try:
                with open(path, "rb") as f:
                    obj = pickle.load(f)
                print(f"[+] {label} loaded from {os.path.basename(path)}")
                return obj
            except Exception as e:
                print(f"[!] {label} load FAILED ({os.path.basename(path)}): {type(e).__name__}: {e}")
                # Diğer adayları denemeye devam et
        print(f"[!] {label} not loaded (heuristik fallback aktif olacak)")
        return None

    phishing_model = _try_load(phishing_paths, "Phishing model")
    spam_model = _try_load(spam_paths, "Spam model")
    vectorizer = _try_load(vectorizer_paths, "Vectorizer")

    return phishing_model is not None and spam_model is not None and vectorizer is not None


def get_gmail_credentials():
    global gmail_account
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        # Correct table name: gmail_hesaplari (was incorrectly GmailAccounts)
        cursor.execute("SELECT eposta, uygulama_sifresi FROM gmail_hesaplari LIMIT 1")
        result = cursor.fetchone()
        conn.close()

        if result:
            gmail_account = {"email": result[0], "password": result[1]}
            return True
    except Exception as e:
        print(f"[!] Database error: {e}")
    return False


# ── Heuristic detectors (always available, even without ML models) ───────────

def heuristic_phishing(text):
    t = text.lower()
    score = 0
    urgency_tr = ["acil", "hemen", "son uyarı", "kapatılacak", "askıya", "24 saat",
                  "iptal edilecek", "zorunlu", "hesabınız", "bloke", "doğrula"]
    sensitive_tr = ["şifre", "parola", "kredi kartı", "tc kimlik", "iban",
                    "banka", "hesap", "yetki", "giriş"]
    action_tr = ["tıkla", "link", "ekteki", "fatura", "indirmek", "giriş yap", "ödeme"]

    urgency_en = ["urgent", "immediate action", "account suspended", "verify now",
                  "click here to restore", "your account will be", "limited access",
                  "confirm your identity", "unusual activity", "security alert"]
    sensitive_en = ["password", "social security", "credit card", "bank account",
                    "login credentials", "ssn", "date of birth", "mother's maiden"]
    action_en = ["click here", "download the attachment", "open the file",
                 "sign in", "log in to your account", "enter your details"]

    for w in urgency_tr + urgency_en:
        if w in t: score += 15
    for w in sensitive_tr + sensitive_en:
        if w in t: score += 20
    for w in action_tr + action_en:
        if w in t: score += 10

    if any(g in t for g in ["değerli müşteri", "sayın kullanıcı", "sayın abonemiz",
                            "dear customer", "dear user", "dear valued"]):
        score += 5

    for d in ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"]:
        if d in t: score += 25

    return min(score, 100)


def heuristic_spam(text):
    t = text.lower()
    score = 0
    # Türkçe spam anahtar kelimeleri — zengin liste (gerçek spam mailler üzerinden derlendi)
    spam_words = [
        # Türkçe
        "bedava", "kampanya", "indirim", "ödül", "kazan", "çekiliş", "fırsat",
        "ucuz", "ucuz fiyat", "alışveriş", "kaçırmayın", "süreli", "sınırlı süre",
        "sadece bugün", "anında", "garanti", "100% garanti", "%100 garanti",
        "para kazan", "kazançlı", "promosyon", "hediye", "kupon",
        # İngilizce
        "special offer", "free", "winner", "congratulations", "prize",
        "you've been selected", "earn money", "make money fast", "work from home",
        "discount", "deal", "bargain", "save money"
    ]
    spam_patterns = [
        # Türkçe
        "tıkla", "tıklayın", "ziyaret edin", "burayı tıkla", "hemen al", "hemen satın",
        "sipariş ver", "şimdi al", "kaçırma", "fırsatı kaçırma", "fırsatı kaçırmayın",
        # İngilizce
        "click here", "act now", "limited time", "exclusive deal",
        "don't miss", "no obligation", "risk free", "100% free",
        "satisfaction guaranteed", "this is not spam"
    ]
    # Yüzde indirim kalıpları (%50, %70, %80, %90 vb.)
    percent_discount_words = ["%50", "%60", "%70", "%80", "%90", "%99", "50% off", "70% off", "90% off"]

    for w in spam_words:
        if w in t: score += 15
    for p in spam_patterns:
        if p in t: score += 20
    for pd in percent_discount_words:
        if pd in t: score += 25  # Büyük yüzde indirimleri → güçlü spam sinyali
    if "!!!" in t or "???" in t: score += 10
    if any(w in t for w in ["buy now", "order now", "subscribe now", "hemen satın", "sipariş ver"]):
        score += 25
    return min(score, 100)


def heuristic_sql_injection(text):
    t = text.lower()
    score = 0
    sql_keywords = [
        "select * from", "select 1 from", "union select", "union all select",
        "drop table", "drop database", "delete from", "insert into",
        "exec(", "execute(", "xp_cmdshell", "sp_executesql",
        "information_schema", "sys.tables", "@@version", "char(0x",
        "' or '1'='1", '" or "1"="1', "or 1=1", "or 1=1--",
        "'; drop", '"; drop', "' --", '" --', "'/*", "/**/",
        "sleep(", "waitfor delay", "benchmark(", "load_file(",
        "into outfile", "into dumpfile", "having 1=1",
    ]
    for kw in sql_keywords:
        if kw in t: score += 30
    if "%27" in t or "%22" in t or "%3d" in t: score += 20
    if "0x" in t and ("select" in t or "exec" in t): score += 25
    return min(score, 100)


def heuristic_xss(text):
    t = text.lower()
    score = 0
    xss_patterns = [
        "<script", "</script>", "javascript:", "onerror=", "onload=",
        "onclick=", "onmouseover=", "onfocus=", "onblur=",
        "alert(", "confirm(", "prompt(", "document.cookie",
        "document.write(", "window.location", "eval(",
        "<img src=", "<iframe", "<object", "<embed",
        "expression(", "vbscript:", "data:text/html",
        "&#x3c;script", "%3cscript", "\\u003cscript",
    ]
    for p in xss_patterns:
        if p in t: score += 25
    if ("&lt;" in t or "&gt;" in t) and ("script" in t or "alert" in t):
        score += 20
    return min(score, 100)


def heuristic_trojan(text, attachment_names=""):
    combined = (text + " " + attachment_names).lower()
    score = 0
    dangerous_exts = [".exe", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
                      ".wsf", ".wsh", ".msi", ".ps1", ".scr", ".pif",
                      ".com", ".hta", ".jar", ".reg", ".lnk"]
    for ext in dangerous_exts:
        if ext in combined: score += 35
    if re.search(r'\.(pdf|doc|xls|zip)\.(exe|bat|vbs|js|cmd)', combined):
        score += 40
    open_cues = [
        "ekteki dosyayı açın", "dosyayı çalıştırın", "kurulum dosyası",
        "open the attachment", "run the file", "execute the installer",
        "double-click", "enable macros", "içeriği etkinleştir", "makroları etkinleştir",
    ]
    for cue in open_cues:
        if cue in combined: score += 20
    for o in ["base64", "powershell -enc", "powershell -e ", "cmd /c "]:
        if o in combined: score += 30
    return min(score, 100)


# ── Main analysis: ML for phishing/spam, heuristics for everything ────────────

def ml_scores(text):
    if not vectorizer or not phishing_model or not spam_model:
        return None, None
    try:
        X = vectorizer.transform([text])
        phishing_prob = phishing_model.predict_proba(X)[0][1]
        spam_prob = spam_model.predict_proba(X)[0][1]
        return round(phishing_prob * 100, 2), round(spam_prob * 100, 2)
    except Exception as e:
        print(f"[!] ML scoring error: {e}")
        return None, None


def analyze_text(text, attachment_names=""):
    ph_ml, sp_ml = ml_scores(text)
    phishing_score = ph_ml if ph_ml is not None else heuristic_phishing(text)
    spam_score     = sp_ml if sp_ml is not None else heuristic_spam(text)

    sql_score    = heuristic_sql_injection(text)
    xss_score    = heuristic_xss(text)
    trojan_score = heuristic_trojan(text, attachment_names)

    # Eşik bantları (C# MLModelService ile aynı tutuluyor):
    #   0-39  -> Güvenli
    #   40-69 -> Şüpheli / Riskli (uyarı, taşıma yok)
    #   70+   -> Kritik (phishing/tehdit -> Çöp Kutusu)
    # Spam ayrı: ≥ 50 -> Spam klasörüne taşı
    is_phishing = phishing_score >= 70
    is_spam     = spam_score >= 50
    is_sql      = sql_score >= 70
    is_xss      = xss_score >= 70
    is_trojan   = trojan_score >= 70
    is_dangerous = is_phishing or is_sql or is_xss or is_trojan

    return {
        "phishing_score":      phishing_score,
        "spam_score":          spam_score,
        "sql_injection_score": sql_score,
        "xss_score":           xss_score,
        "trojan_score":        trojan_score,
        "is_phishing":         is_phishing,
        "is_spam":             is_spam,
        "has_sql_injection":   is_sql,
        "has_xss":             is_xss,
        "has_trojan":          is_trojan,
        "is_dangerous":        is_dangerous,
        "ml_used":             ph_ml is not None,
    }


# ── Background Gmail sync: spam -> Spam, threats -> permanent delete ───────────

def sync_and_analyze_gmail():
    if not gmail_account:
        print("[!] No Gmail account configured")
        return

    print(f"[*] Syncing Gmail for {gmail_account['email']}")
    try:
        with MailBox("imap.gmail.com").login(gmail_account["email"], gmail_account["password"]) as mailbox:
            for msg in mailbox.fetch(AND(limit=20), reverse=True):
                subject = msg.subject or ""
                body = msg.text or ""
                attachments = " ".join(att.filename or "" for att in msg.attachments)
                result = analyze_text(f"{subject} {body}", attachments)

                threats = []
                if result["is_phishing"]:        threats.append("PHISHING")
                if result["has_sql_injection"]:  threats.append("SQL-INJECT")
                if result["has_xss"]:            threats.append("XSS")
                if result["has_trojan"]:         threats.append("TROJAN")
                if result["is_spam"]:            threats.append("SPAM")
                label = ", ".join(threats) if threats else "clean"
                print(f"  [-] {subject[:40]!r} -> {label}")

                try:
                    if result["is_dangerous"]:
                        # Permanently delete dangerous mail
                        mailbox.delete(msg.uid)
                        print(f"     [!] THREAT permanently deleted from inbox")
                    elif result["is_spam"]:
                        mailbox.move(msg.uid, "[Gmail]/Spam")
                        print(f"     [~] Moved to Spam")
                except Exception as e:
                    print(f"     [!] Move/delete error: {e}")

    except Exception as e:
        print(f"[!] Gmail sync error: {e}")


def background_scheduler():
    print("[*] Background scheduler started — running every 60 s")
    while True:
        if get_gmail_credentials():
            sync_and_analyze_gmail()
        time.sleep(60)


# ── Flask routes ──────────────────────────────────────────────────────────────

@app.route("/analyze", methods=["POST"])
def analyze():
    auth = request.headers.get("x-api-key", "")
    if auth != INTERNAL_AUTH_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    if not data or "text" not in data:
        return jsonify({"error": "Missing 'text' parameter"}), 400

    text = data["text"]
    attachments = data.get("attachment_names", "")
    return jsonify(analyze_text(text, attachments))


@app.route("/health", methods=["GET"])
def health():
    models_loaded = phishing_model is not None and spam_model is not None and vectorizer is not None
    return jsonify({
        "status": "running",
        "models_loaded": models_loaded,
        "gmail_connected": gmail_account is not None,
        "detectors": ["phishing", "spam", "sql_injection", "xss", "trojan"],
    })


@app.route("/sync", methods=["POST"])
def sync():
    if not gmail_account:
        return jsonify({"error": "No Gmail account configured"}), 400
    sync_and_analyze_gmail()
    return jsonify({"status": "sync completed"})


if __name__ == "__main__":
    print("=" * 55)
    print("  CyberSecurityAssistant Flask API")
    print("  Detectors: Phishing | Spam | SQL Injection | XSS | Trojan")
    print("  Spam -> Spam folder | Threats -> permanent delete")
    print("=" * 55)

    if load_models():
        print("[+] All ML models loaded")
    else:
        print("[!] Some models missing — heuristic fallback active")

    if get_gmail_credentials():
        print(f"[+] Gmail account: {gmail_account['email']}")
    else:
        print("[!] No Gmail account in DB — background sync disabled")

    threading.Thread(target=background_scheduler, daemon=True).start()
    print("[*] Starting Flask server on http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
