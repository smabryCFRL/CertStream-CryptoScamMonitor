# REPLACE THE * WITH YOUR LOCAL PI's USERNAME

import time
import os
import requests
import urllib3
import threading
import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# we subtract 6 hours because the script can take a long time to run causing it to go to the next day
# before it finishes . basically dont run this script before between 12am - 6 am ...
# i know there is a better way to fix this
adjusted_time = datetime.datetime.now() - datetime.timedelta(hours=6)
today = adjusted_time.strftime("%Y-%m-%d")
# change * to your local username
INPUT_FILE = f"/home/*/scam_logs/targets_{today}.txt"
OUTPUT_FILE = f"/home/*/scam_logs/confirmed_{today}.txt"

CRYPTO_TERMS = ['bitcoin', 'usdt']
HYIP_TERMS = ['daily roi', 'investment plan']

active_threats = []
seen_urls = set()
write_lock = threading.Lock()

if os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, 'r') as f:
        # Adds already confirmed URLs to seen_urls so they are skipped instantly
        for line in f:
            url = line.strip()
            if url:
                seen_urls.add(url)

def check_html_and_save(target):
    # Ensure URL is clean for comparison
    strict_url = target if target.startswith("http") else f"https://{target}/"
    
    # do i even need this if its a set ??? what was i thinking will fix tmmrw
    if strict_url in seen_urls: 
        return
        
    try:
        response = requests.get(strict_url, timeout=5, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
        
        if response.status_code == 200:
            html_body = response.text.lower()
            
            crypto_hits = sum(1 for term in CRYPTO_TERMS if term in html_body)
            hyip_hits = sum(1 for term in HYIP_TERMS if term in html_body)
            
            if crypto_hits >= 1 and hyip_hits >= 2:
                print(f"[+] NEW SCAM CONFIRMED: {strict_url}")
                with write_lock:
                    active_threats.append(strict_url)
                    # Using "a" for append mode ensures we don't overwrite morning hits
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
        
    # Filter out targets already in seen_urls to give an accurate count
    new_targets = [t for t in targets if (t if t.startswith("http") else f"https://{t}/") not in seen_urls]
    
    print(f"[*] Loaded {len(seen_urls)} already confirmed scams.")
    print(f"[*] Scanning {len(new_targets)} NEW targets from today's log...\n")
    
    threads = []
    for target in new_targets:
        t = threading.Thread(target=check_html_and_save, args=(target,))
        threads.append(t)
        t.start()

        time.sleep(0.1) # this helps whenver you run this script at the same time as live_sniper.py
        if len(threads) >= 20:
            for t in threads: t.join()
            threads = []
            
    for t in threads: t.join()
        
    print(f"\n[+] Complete! Added {len(active_threats)} NEW scams to {OUTPUT_FILE}.")
