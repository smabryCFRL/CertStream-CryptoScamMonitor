# REPLACE THE * WITH YOUR LOCAL PI's USERNAME
import os
import time
import requests
import urllib3
import datetime
import threading
import re
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# daily logging - makes a new file every day
adjusted_time = datetime.datetime.now() - datetime.timedelta(hours=6)
today = adjusted_time.strftime("%Y-%m-%d")
INPUT_FILE = f"/home/*/scam_logs/targets_{today}.txt"
OUTPUT_FILE = f"/home/*/scam_logs/confirmed_{today}.txt"

# using Regex is better than for loopsfor keyword detection in most cases
# since it compiles to C and runs in 0(n) time - \b ensures we only match whole words
CRYPTO_REGEX = re.compile(r'\b(bitcoin|usdt|ethereum|crypto|wallet address|deposit amount|withdraw)\b')
HYIP_REGEX = re.compile(r'\b(daily roi|investment plan|standard plan|premium plan|daily return|silver plan|gold plan|mining plan|referral commission|minimum deposit|task center|frozen amount|recharge)\b')

active_threats = []
seen_urls = set()
write_lock = threading.Lock()

# preload files into memory to avoid re-reading the same file multiple times during execution
if os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, 'r') as f:
        for line in f:
            url = line.strip()
            if url: seen_urls.add(url)

def check_html_and_save(target):
    base_target = target if not target.startswith("http") else target.split("//")[-1]
    
    # try HTTPS first, but we need to know the base URL
    strict_url = f"https://{base_target}/"
    if strict_url in seen_urls: return
        
    try:
        # stream=True prevents massive downloads
        response = requests.get(strict_url, timeout=(3, 5), verify=False,
                            headers={'User-Agent': 'Mozilla/5.0'}, stream=True)
        
        if response.status_code == 200:
            # we only read the first 75KB of the HTML to check for keywords, which is usually enough to confirm a scam
            html_body = ""
            for chunk in response.iter_content(chunk_size=75000):
                if chunk:
                    html_body = chunk.decode('utf-8', errors='ignore').lower()
                    break 
            
            crypto_hits = len(set(CRYPTO_REGEX.findall(html_body)))
            hyip_hits = len(set(HYIP_REGEX.findall(html_body)))
            
            if crypto_hits >= 1 and hyip_hits >= 2:
                print(f"[+] NEW SCAM CONFIRMED: {strict_url}")
                
                with write_lock:
                    active_threats.append(strict_url)
                    with open(OUTPUT_FILE, "a") as file:
                        file.write(f"{strict_url}\n")
                    seen_urls.add(strict_url)
            else:
                pass
                
    except requests.RequestException as e:
        pass

if __name__ == "__main__":
    if not os.path.exists(INPUT_FILE):
        print(f"[-] No targets found for today ({INPUT_FILE}). Exiting.")
        exit()
        
    with open(INPUT_FILE, "r") as file:
        targets = [line.strip() for line in file if line.strip()]
        
    new_targets = [t for t in targets if (t if t.startswith("http") else f"https://{t}/") not in seen_urls]
    
    print(f"[*] Loaded {len(seen_urls)} already confirmed scams.")
    print(f"[*] Scanning {len(new_targets)} NEW targets from today's log...\n")
    
    # replace manual threading with ThreadPoolExecutor for better performance and cleaner code
    with ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(check_html_and_save, new_targets)
        
    print(f"\n[+] Complete! Added {len(active_threats)} NEW scams to {OUTPUT_FILE}.")
    
    if len(new_targets) > 0:
        hit_rate = (len(active_threats) / len(new_targets)) * 100
        print(f"[*] Session Hit Rate: {hit_rate:.2f}% ({len(active_threats)}/{len(new_targets)} scanned)")
    else:
        print("[*] Session Hit Rate: N/A (0 new targets scanned)")
