import time
import pyperclip
import requests
from plyer import notification

BACKEND_URL = "http://127.0.0.1:8000/predict"
CHECK_INTERVAL = 2  # seconds

last_clipboard = ""

def is_url(text: str) -> bool:
    return text.startswith("http://") or text.startswith("https://")

def check_phishing(url: str) -> bool:
    try:
        response = requests.post(BACKEND_URL, json={"url": url}, timeout=5)
        if response.status_code == 200:
            result = response.json()
            return result.get("prediction", "").lower() == "phishing"
        return False
    except Exception as e:
        print(f"[!] Error contacting backend: {e}")
        return False

while True:
    try:
        current_clipboard = pyperclip.paste().strip()
        if current_clipboard != last_clipboard and is_url(current_clipboard):
            last_clipboard = current_clipboard
            print(f"[+] Checking URL: {current_clipboard}")

            if check_phishing(current_clipboard):
                notification.notify(
                    title="⚠ Phishing Alert!",
                    message=f"Suspicious link detected:\n{current_clipboard}",
                    timeout=5
                )
                print("[!] Phishing detected!")
            else:
                print("[OK] Link is clean.")
    except Exception as e:
        print(f"[ERROR] {e}")
    time.sleep(CHECK_INTERVAL)
