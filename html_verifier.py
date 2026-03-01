import os
import requests
import urllib3
import threading
import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# DYNAMIC DAILY LOGGING
today = datetime.datetime.now().strftime("%Y-%m-%d")
INPUT_FILE = f"/home/*/scam_logs/targets_{today}.txt"
OUTPUT_FILE = f"/home/*/scam_logs/confirmed_{today}.txt"
# Replace * with your local username

# INTERSECTION DICTIONARIES
CRYPTO_TERMS = ['bitcoin', 'usdt', 'ethereum', 'crypto', 'wallet address', 'deposit amount', 'withdraw']
HYIP_TERMS = ['daily roi', 'investment plan', 'standard plan', 'premium plan', 'daily return', 'silver plan', 'gold plan', 'mining plan', 'referral commission', 'minimum deposit', 'task center', 'frozen amount', 'recharge']

active_threats = []
seen_urls = set()
write_lock = threading.Lock()

def check_html_and_save(target):
    strict_url = target if target.startswith("http") else f"https://{target}/"
    if strict_url in seen_urls: return
        
    try:
        # 5-second timeout is critical so dead servers don't stall the Pi
        response = requests.get(strict_url, timeout=5, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
        
        if response.status_code == 200:
            html_body = response.text.lower()
            
            crypto_hits = sum(1 for term in CRYPTO_TERMS if term in html_body)
            hyip_hits = sum(1 for term in HYIP_TERMS if term in html_body)
            
            # Must have 1 Crypto footprint AND 2 HYIP footprints
            if crypto_hits >= 1 and hyip_hits >= 2:
                print(f"[+] SCAM CONFIRMED: {strict_url}")
                with write_lock:
                    active_threats.append(strict_url)
                    with open(OUTPUT_FILE, "a") as file:
                        file.write(f"{strict_url}\n")
                    seen_urls.add(strict_url)
    except Exception: pass 

if __name__ == "__main__":
    if not os.path.exists(INPUT_FILE):
        print(f"[-] No targets found for today ({INPUT_FILE}). Exiting.")
        exit()
        
    with open(INPUT_FILE, "r") as file:
        targets = [line.strip() for line in file if line.strip()]
        
    print(f"[*] Scanning {len(targets)} targets from today's log...\n")
    
    threads = []
    for target in targets:
        t = threading.Thread(target=check_html_and_save, args=(target,))
        threads.append(t)
        t.start()
        
        # Only 20 threads for Raspberry Pi stability
        if len(threads) >= 20:
            for t in threads: t.join()
            threads = []
            
    for t in threads: t.join()
        
    print(f"\n[+] Complete! Saved {len(active_threats)} active scams to {OUTPUT_FILE}.")
