import os
import sys
import time
import subprocess
import threading
import urllib.request
import re
import qrcode

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
CLOUDFLARED_PATH = os.path.join(BASE_DIR, "cloudflared.exe")
CLOUDFLARED_URL = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"

def ensure_cloudflared():
    if os.path.exists(CLOUDFLARED_PATH):
        return True

    print("[*] Downloading Cloudflare Public Tunnel client for Windows (one-time setup)...")
    try:
        urllib.request.urlretrieve(CLOUDFLARED_URL, CLOUDFLARED_PATH)
        print("[+] Cloudflared downloaded successfully.")
        return True
    except Exception as e:
        print(f"[-] Could not download cloudflared: {e}")
        return False

def start_flask():
    from app import app, SERVER_PORT
    app.run(host="0.0.0.0", port=SERVER_PORT, debug=False, use_reloader=False)

def main():
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')

    print("=" * 70)
    print("🌐 CYBER TRIAGE TOOL - GLOBAL PUBLIC INTERNET ACCESS")
    print("=" * 70)
    print("[*] Launching local forensic analysis backend...")

    # Start Flask in background daemon thread
    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()
    time.sleep(2)

    has_cf = ensure_cloudflared()

    if has_cf:
        print("[*] Establishing secure public HTTPS tunnel with Cloudflare...")
        cmd = [CLOUDFLARED_PATH, "tunnel", "--url", "http://127.0.0.1:5000"]
        
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace'
        )

        public_url = None
        start_time = time.time()

        for line in proc.stdout:
            # Look for trycloudflare.com URL in cloudflared logs
            match = re.search(r'https://[a-zA-Z0-9-]+\.trycloudflare\.com', line)
            if match:
                public_url = match.group(0)
                break
            if time.time() - start_time > 30:
                break

        if public_url:
            print("\n" + "=" * 70)
            print("🚀 YOUR WEBSITE IS NOW LIVE ACROSS THE WORLD ON THE INTERNET!")
            print("=" * 70)
            print(f"[+] 🌍 GLOBAL PUBLIC HTTPS URL (Share with anyone on any network):")
            print(f"    -> {public_url}")
            print("")
            print("[+] Users on any mobile network (4G/5G) or different Wi-Fi can:")
            print("    1. Open the URL on their phone or laptop.")
            print("    2. Upload evidence files (.log, .txt, .json, .csv, .pcap).")
            print("    3. View live AI triage and download PDF reports.")
            print("=" * 70)
            
            # Print QR Code
            try:
                qr = qrcode.QRCode()
                qr.add_data(public_url)
                qr.make(fit=True)
                print("[+] Scan this QR code from any mobile phone worldwide:")
                qr.print_ascii(invert=True)
            except Exception:
                pass

            print("\n[*] Keep this window open while you want others to access your tool.")
            print("=" * 70)

            # Keep process running
            try:
                proc.wait()
            except KeyboardInterrupt:
                print("\n[*] Stopping public tunnel...")
                proc.terminate()
        else:
            print("[-] Could not retrieve Cloudflare public URL. Running on local network.")
    else:
        print("[-] Fallback: Running on local network.")
        flask_thread.join()

if __name__ == "__main__":
    main()
