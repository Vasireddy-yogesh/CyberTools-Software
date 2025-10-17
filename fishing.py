import time
import pyperclip
import requests
import pandas as pd
from plyer import notification
from urllib.parse import urlparse
import os
import threading

# ==================== CONFIG ====================
BACKEND_URL = "http://127.0.0.1:8000/predict"  # FastAPI phishing API
CSV_PATH = r"C:\phishing_detector\phishing_emails.csv"  # Local CSV dataset
CHECK_INTERVAL = 1  # seconds
LOG_FILE = r"C:\phishing_detector\phishing_log.txt"
# =================================================

# ==================== LOGGING ====================
def log_event(msg):
    os.makedirs(os.path.dirname(LOG_FILE) or ".", exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")

# ==================== POPUP ALERT ====================
def send_popup(title, message):
    notification.notify(title=title, message=message, timeout=5)

# ==================== URL NORMALIZATION ====================
def normalize_url(url):
    try:
        parsed = urlparse(url.strip())
        domain = parsed.netloc.lower() if parsed.netloc else ""
        path = parsed.path.lower().rstrip("/")
        if not domain:
            parsed = urlparse("http://" + url.strip())
            domain = parsed.netloc.lower()
            path = parsed.path.lower().rstrip("/")
        return domain + path
    except Exception:
        return url.strip().lower()

# ==================== LOAD LOCAL DATASET ====================
def load_phishing_dataset():
    if not os.path.exists(CSV_PATH):
        print(f"[!] CSV dataset not found at {CSV_PATH}, skipping local check.")
        return set()
    try:
        df = pd.read_csv(CSV_PATH, on_bad_lines='skip', engine='python')
        if "url" in df.columns:
            urls = df["url"].astype(str)
        elif "domain" in df.columns:
            urls = df["domain"].astype(str)
        else:
            urls = df.iloc[:, 0].astype(str)
        normalized = {normalize_url(u) for u in urls if isinstance(u, str)}
        print(f"[+] Loaded {len(normalized)} phishing entries from dataset.")
        return normalized
    except Exception as e:
        print(f"[!] Failed to read dataset: {e}")
        return set()

# ==================== CHECK WITH BACKEND ====================
def check_with_backend(url):
    try:
        response = requests.post(BACKEND_URL, json={"url": url}, timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get("prediction") == "phishing":
                send_popup("⚠️ Phishing Alert!", f"Detected by AI model:\n{url}")
                log_event(f"ML Detected phishing: {url}")
                return True
    except Exception as e:
        log_event(f"[Backend Error] {e}")
    return False

# ==================== MONITOR CLIPBOARD ====================
def monitor_clipboard(phishing_data):
    print("[*] Windows Guard started: monitoring clipboard for phishing URLs...")
    last_clip = ""
    while True:
        try:
            clip_text = pyperclip.paste().strip()
            if not clip_text or clip_text == last_clip:
                time.sleep(CHECK_INTERVAL)
                continue

            last_clip = clip_text
            if clip_text.startswith("http://") or clip_text.startswith("https://"):
                normalized = normalize_url(clip_text)
                # First check local dataset
                if normalized in phishing_data:
                    send_popup("⚠️ Phishing Alert!", f"Found in dataset:\n{clip_text}")
                    log_event(f"Local dataset detected phishing: {clip_text}")
                else:
                    # Check backend asynchronously to not block clipboard monitoring
                    threading.Thread(target=check_with_backend, args=(clip_text,), daemon=True).start()

        except Exception as e:
            log_event(f"[Error] {e}")

        time.sleep(CHECK_INTERVAL)

# ==================== MAIN ====================
if __name__ == "__main__":
    phishing_data = load_phishing_dataset()
    monitor_clipboard(phishing_data)
