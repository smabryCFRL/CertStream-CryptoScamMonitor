# REPLACE THE * WITH YOUR LOCAL PI's USERNAME

import os
import requests
import urllib3
import threading
import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Daily logging | I have a cron job set to run at 11:50pm every night to run this script .
# The time it takes for this script to complete is longer than 10 minutes so we subtract 
# 6 hours from the time to ensure there are no errors with saving data to the wrong file .
adjusted_time = datetime.datetime.now() - datetime.timedelta(hours=6)
today = adjusted_time.strftime("%Y-%m-%d")
INPUT_FILE = f"/home/*/scam_logs/targets_{today}.txt"
OUTPUT_FILE = f"/home/*/scam_logs/confirmed_{today}.txt"

# Create your own keywords !
CRYPTO_TERMS = ['bitcoin', 'crypto']
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
    
    if strict_url in seen_urls: 
        return
        
    try:
        response = requests.get(strict_url, timeout=5, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
        
        if response.status_code == 200:
            html_body = response.text.lower()
            
            crypto_hits = sum(1 for term in CRYPTO_TERMS if term in html_body)
            hyip_hits = sum(1 for term in HYIP_TERMS if term in html_body)

            # the logic behing deciding which websites to return . edit this to get more or less returns .
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
        
        if len(threads) >= 20: # This is at 20 since I am using a rasberry Pi and I dont want to destroy it . If you can run 100 threads ... do it !!!
            for t in threads: t.join()
            threads = []
            
    for t in threads: t.join()
        
    print(f"\n[+] Complete! Added {len(active_threats)} NEW scams to {OUTPUT_FILE}.")
