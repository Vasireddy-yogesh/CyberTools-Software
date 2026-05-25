import os
import sys
import winreg

def setup_registry():
    """
    Registers this application as a Web Browser in Windows.
    This allows the user to select 'CyberSecure' as the Default Browser,
    enabling global link interception across the OS.
    NOTE: Must be run as Administrator!
    """
    if sys.platform != "win32":
        print("This script is only for Windows.")
        return

    # Path to the python executable and the app.py script
    python_exe = sys.executable
    app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "app.py"))
    
    # The command that Windows will run when a link is clicked
    # We pass --handle-url followed by "%1" (which Windows replaces with the URL)
    command = f'"{python_exe}" "{app_path}" --handle-url "%1"'
    
    app_name = "CyberSecurePhishingGuard"
    app_display_name = "CyberSecure Phishing Guard"
    
    try:
        # 1. Register the application in Software\Classes
        # HKEY_LOCAL_MACHINE requires Admin rights. We use HKEY_CURRENT_USER to avoid needing admin, 
        # but sometimes HKCU is not enough for Default Browser. Let's try HKCU first.
        
        base_key = winreg.HKEY_CURRENT_USER
        classes_path = f"Software\\Classes\\{app_name}"
        
        # Create class
        with winreg.CreateKey(base_key, classes_path) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, app_display_name)
            winreg.SetValueEx(key, "URL Protocol", 0, winreg.REG_SZ, "")
            
        # Create DefaultIcon
        with winreg.CreateKey(base_key, f"{classes_path}\\DefaultIcon") as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, f"{python_exe},0")
            
        # Create shell\open\command
        with winreg.CreateKey(base_key, f"{classes_path}\\shell\\open\\command") as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, command)
            
        # 2. Register for HTTP and HTTPS protocols explicitly
        for proto in ["http", "https"]:
            proto_path = f"Software\\Classes\\{proto}\\shell\\open\\command"
            try:
                # This might require admin if HKLM, but we are in HKCU.
                # Actually, overriding http/https in HKCU\Software\Classes\http is the standard way.
                with winreg.CreateKey(base_key, proto_path) as key:
                    # We might not want to force overwrite the existing http handler directly here,
                    # but rather register it in StartMenuInternet.
                    pass
            except Exception:
                pass

        # 3. Register in StartMenuInternet so it shows up in "Default Apps"
        smi_path = f"Software\\Clients\\StartMenuInternet\\{app_name}"
        with winreg.CreateKey(base_key, smi_path) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, app_display_name)
            
        with winreg.CreateKey(base_key, f"{smi_path}\\Capabilities") as key:
            winreg.SetValueEx(key, "ApplicationName", 0, winreg.REG_SZ, app_display_name)
            winreg.SetValueEx(key, "ApplicationDescription", 0, winreg.REG_SZ, "Intercepts and scans links for phishing.")
            
        with winreg.CreateKey(base_key, f"{smi_path}\\Capabilities\\URLAssociations") as key:
            winreg.SetValueEx(key, "http", 0, winreg.REG_SZ, app_name)
            winreg.SetValueEx(key, "https", 0, winreg.REG_SZ, app_name)

        with winreg.CreateKey(base_key, f"{smi_path}\\shell\\open\\command") as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, command)

        # 4. Register the Application under RegisteredApplications
        reg_app_path = "Software\\RegisteredApplications"
        with winreg.CreateKey(base_key, reg_app_path) as key:
            winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, f"Software\\Clients\\StartMenuInternet\\{app_name}\\Capabilities")

        print("✅ Registry Setup Complete!")
        print("Now go to Windows Settings -> Apps -> Default Apps.")
        print("Search for 'Web Browser' and select 'CyberSecure Phishing Guard'.")
        
    except PermissionError:
        print("❌ Permission Error: Please run this script as Administrator to modify registry keys.")
    except Exception as e:
        print(f"❌ Error setting up registry: {e}")

if __name__ == "__main__":
    setup_registry()
