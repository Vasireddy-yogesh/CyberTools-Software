import customtkinter as ctk
import pyperclip
import threading
import time
import sys
import os
import re
import urllib.parse
import warnings
from plyer import notification

warnings.filterwarnings("ignore")

from url_analyzer import analyze_url

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class CyberSecureApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CyberSecure Unified Dashboard")
        self.geometry("900x600")
        
        # UI State
        self.clipboard_monitor_active = ctk.BooleanVar(value=True)
        self.logs = []
        self.running = True
        
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # ----------------- SIDEBAR -----------------
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(5, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="🛡️ CyberSecure", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 30))

        self.btn_phishing = ctk.CTkButton(self.sidebar_frame, text="Phishing Guard", command=self.show_phishing_frame)
        self.btn_phishing.grid(row=1, column=0, padx=20, pady=10)

        self.btn_firewall = ctk.CTkButton(self.sidebar_frame, text="Firewall (Soon)", fg_color="transparent", border_width=1, state="disabled")
        self.btn_firewall.grid(row=2, column=0, padx=20, pady=10)

        self.btn_vpn = ctk.CTkButton(self.sidebar_frame, text="Secure VPN (Soon)", fg_color="transparent", border_width=1, state="disabled")
        self.btn_vpn.grid(row=3, column=0, padx=20, pady=10)

        self.btn_edr = ctk.CTkButton(self.sidebar_frame, text="EDR Agent (Soon)", fg_color="transparent", border_width=1, state="disabled")
        self.btn_edr.grid(row=4, column=0, padx=20, pady=10)

        # ----------------- MAIN CONTENT: PHISHING GUARD -----------------
        self.phishing_frame = ctk.CTkFrame(self, corner_radius=10)
        self.phishing_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.phishing_frame.grid_columnconfigure(0, weight=1)
        self.phishing_frame.grid_rowconfigure(2, weight=1)

        self.phishing_title = ctk.CTkLabel(self.phishing_frame, text="Phishing Guard", font=ctk.CTkFont(size=24, weight="bold"))
        self.phishing_title.grid(row=0, column=0, padx=20, pady=20, sticky="w")

        # Controls
        self.controls_frame = ctk.CTkFrame(self.phishing_frame)
        self.controls_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        self.controls_frame.grid_columnconfigure(1, weight=1)

        self.lbl_status = ctk.CTkLabel(self.controls_frame, text="Clipboard Monitor: ACTIVE", text_color="#33cc33", font=ctk.CTkFont(weight="bold"))
        self.lbl_status.grid(row=0, column=0, padx=20, pady=20)

        self.switch_monitor = ctk.CTkSwitch(self.controls_frame, text="Enable Protection", variable=self.clipboard_monitor_active, command=self.toggle_monitor)
        self.switch_monitor.grid(row=0, column=1, padx=20, pady=20, sticky="e")

        # Logs
        self.logs_textbox = ctk.CTkTextbox(self.phishing_frame, font=ctk.CTkFont(family="Consolas", size=12))
        self.logs_textbox.grid(row=2, column=0, padx=20, pady=20, sticky="nsew")
        self.logs_textbox.insert("0.0", "--- Guard Active: Waiting for URLs in clipboard ---\n")
        self.logs_textbox.configure(state="disabled")

        # Start background thread
        self.monitor_thread = threading.Thread(target=self.clipboard_monitor_loop, daemon=True)
        self.monitor_thread.start()

    def on_closing(self):
        self.running = False
        self.destroy()

    def show_phishing_frame(self):
        self.phishing_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)

    def toggle_monitor(self):
        if self.clipboard_monitor_active.get():
            self.lbl_status.configure(text="Clipboard Monitor: ACTIVE", text_color="#33cc33")
            self.log_message("Monitoring resumed.")
        else:
            self.lbl_status.configure(text="Clipboard Monitor: PAUSED", text_color="#cc3333")
            self.log_message("Monitoring paused.")

    def log_message(self, msg):
        if not self.winfo_exists():
            return
        self.logs_textbox.configure(state="normal")
        time_str = time.strftime("%H:%M:%S")
        self.logs_textbox.insert("end", f"[{time_str}] {msg}\n")
        self.logs_textbox.see("end")
        self.logs_textbox.configure(state="disabled")

    def show_popup_alert(self, url, confidence):
        # We can use plyer for a native windows notification
        try:
            notification.notify(
                title="⚠️ Phishing Alert!",
                message=f"Malicious link detected in clipboard!\n{url}\nRisk: {confidence*100:.0f}%",
                app_name="CyberSecure",
                timeout=5
            )
        except Exception:
            pass

        # Also show a UI Popup
        popup = ctk.CTkToplevel(self)
        popup.title("Phishing Detected")
        popup.geometry("500x250")
        popup.attributes("-topmost", True)
        
        lbl_icon = ctk.CTkLabel(popup, text="🚨", font=ctk.CTkFont(size=50))
        lbl_icon.pack(pady=(20,0))
        
        lbl_warn = ctk.CTkLabel(popup, text="Phishing URL Detected!", font=ctk.CTkFont(size=20, weight="bold"), text_color="#ff4444")
        lbl_warn.pack(pady=10)
        
        lbl_url = ctk.CTkTextbox(popup, height=50)
        lbl_url.pack(padx=20, fill="x")
        lbl_url.insert("0.0", url)
        lbl_url.configure(state="disabled")

    def clipboard_monitor_loop(self):
        last_clipboard = ""
        url_pattern = re.compile(r"^https?://[^\s]+", re.IGNORECASE)

        while self.running:
            time.sleep(1.5)
            if not self.clipboard_monitor_active.get():
                continue

            try:
                content = pyperclip.paste().strip()
                if content != last_clipboard:
                    last_clipboard = content
                    
                    if url_pattern.match(content):
                        # Use our actual local analyzer!
                        self.log_message(f"Checking URL: {content}")
                        decision, confidence, meta = analyze_url(content)
                        
                        if decision == "phishing":
                            self.log_message(f"🚨 BLOCKED: {content} (Risk: {confidence})")
                            self.after(0, self.show_popup_alert, content, confidence)
                        else:
                            self.log_message(f"✅ Safe: {content}")
            except Exception as e:
                pass


# =========================================================
# CLI / Protocol Handler Mode
# =========================================================
def handle_clicked_url(url):
    """
    If the app is set as the default browser, this runs when a user clicks a link.
    """
    print(f"Intercepted Link Click: {url}")
    decision, confidence, meta = analyze_url(url)
    
    if decision == "phishing":
        print("Phishing detected! Redirecting to block page...")
        block_page_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "block_page.html"))
        safe_url = urllib.parse.quote(url, safe='')
        block_url = f"file:///{block_page_path}?url={safe_url}"
        
        # Open in Edge (Guaranteed to exist on Windows)
        os.system(f'start msedge "{block_url}"')
    else:
        print("Link is safe. Forwarding to browser...")
        # Open in Edge
        os.system(f'start msedge "{url}"')


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--handle-url":
        # We were launched as the default browser to intercept a click!
        target_url = sys.argv[2]
        handle_clicked_url(target_url)
        sys.exit(0)
    else:
        # Normal Dashboard Mode
        app = CyberSecureApp()
        app.mainloop()
