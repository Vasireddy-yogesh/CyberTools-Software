from phishing_logic import detect_phishing

def run_app():
    print("🔐 Welcome to CyberSecure!")
    user_input = input("Enter a URL or email message to scan for phishing: ")

    result = detect_phishing(user_input)

    if result == 1:
        print("⚠️ Phishing Detected!")
    else:
        print("✅ Safe!")

# Start the app
run_app()
