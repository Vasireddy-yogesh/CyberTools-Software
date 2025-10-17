import time
import psutil
import re
import os
from win10toast import ToastNotifier

CHECK_INTERVAL = 5  # seconds
LOG_FILE = "C:/ProgramData/MyEDR/edr_log.txt"

# Ensure log folder exists
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# Suspicious process keywords
SUSPICIOUS_KEYWORDS = ["keylogger", "rat", "miner", "hack", "stealer"]

# Track processes that already triggered an alert
alerted_processes = set()

# Initialize Windows notifier
toaster = ToastNotifier()

def is_suspicious(proc_name: str) -> bool:
    """Return True if process name contains a suspicious keyword (whole word match)"""
    name_lower = proc_name.lower()
    for word in SUSPICIOUS_KEYWORDS:
        if re.search(rf"\b{re.escape(word)}\b", name_lower):
            return True
    return False

def log_detection(proc_name: str, pid: int):
    with open(LOG_FILE, "a") as f:
        f.write(f"{time.ctime()} - PID: {pid} - Suspicious process: {proc_name}\n")

while True:
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            pid = proc.info['pid']
            name = proc.info['name'] or ""

            if is_suspicious(name) and pid not in alerted_processes:
                # Show notification
                toaster.show_toast(
                    "⚠ EDR Alert!",
                    f"Suspicious process detected:\n{name} (PID: {pid})",
                    duration=5,
                    threaded=True
                )
                print(f"[!] Suspicious process: {name} (PID: {pid})")
                log_detection(name, pid)
                alerted_processes.add(pid)

        # Remove PIDs that are no longer running
        current_pids = {proc.info['pid'] for proc in psutil.process_iter(['pid'])}
        alerted_processes = {pid for pid in alerted_processes if pid in current_pids}

    except Exception as e:
        print(f"[ERROR] {e}")

    time.sleep(CHECK_INTERVAL)
