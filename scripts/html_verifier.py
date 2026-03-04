# REPLACE THE * WITH YOUR LOCAL PI's USERNAME
import os
import sys
import requests
import urllib3
import datetime
import threading
import re
from pathlib import Path
from zoneinfo import ZoneInfo
from concurrent.futures import ThreadPoolExecutor

from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# load .env from project root (one level up from scripts/)
_env_file = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(_env_file)

# proxy config (IP-whitelisted on Decodo dashboard — no creds needed in URL)
PROXY_HOST = os.getenv("PROXY_HOST", "")
PROXY_PORT = os.getenv("PROXY_PORT", "")

if not PROXY_HOST or not PROXY_PORT:
    print("[-] PROXY_HOST and PROXY_PORT must be set in .env. Exiting.")
    sys.exit(1)

PROXIES = {
    "http": f"http://{PROXY_HOST}:{PROXY_PORT}",
    "https": f"http://{PROXY_HOST}:{PROXY_PORT}",
}
print("[+] Proxy configured.")

# daily logging - makes a new file every day
today = datetime.datetime.now(tz=ZoneInfo("US/Central")).strftime("%Y-%m-%d")
INPUT_FILE = f"/home/*/scam_logs/targets_{today}.txt"
OUTPUT_FILE = f"/home/*/scam_logs/confirmed_{today}.txt"

# using Regex is better than for loops for keyword detection in most cases
# since it compiles to C and runs in O(n) time - \b ensures we only match whole words
CRYPTO_REGEX = re.compile(r'\b(bitcoin|btc|ethereum|eth|usdt|tether|bnb|trx|tron|solana|litecoin|dogecoin|crypto|blockchain|mining|staking|defi|web3|wallet|token|hash|miner)\b')
HYIP_REGEX = re.compile(r'\b(daily roi|investment plan|guaranteed profit|passive income|earn daily|referral bonus|minimum deposit|instant withdrawal|compound interest|high yield|roi calculator|deposit now|start earning|join now and earn|guaranteed return|forex trading|copy trading|auto trading)\b')

# structural signals — HYIP template DNA detectable from raw HTML
SCAM_STRUCTURE_REGEX = re.compile(
    r'(class=["\'](?:plan-card|pricing-table|investment-box|deposit-form)["\']'
    r'|<select[^>]*(?:coin|currency|crypto)[^>]*>'
    r'|<input[^>]*(?:deposit|invest|amount)[^>]*>'
    r'|\b(?:200%|300%|500%|1000%)\s*(?:roi|return|profit)'
    r'|(?:telegram|t\.me/)\w+'
    r'|<marquee\b'
    r')',
    re.IGNORECASE
)

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
                            headers={'User-Agent': 'Mozilla/5.0'}, stream=True,
                            proxies=PROXIES)
        
        if response.status_code == 200:
            # we only read the first 75KB of the HTML to check for keywords, which is usually enough to confirm a scam
            html_body = ""
            for chunk in response.iter_content(chunk_size=75000):
                if chunk:
                    html_body = chunk.decode('utf-8', errors='ignore').lower()
                    break 
            
            crypto_hits = len(set(CRYPTO_REGEX.findall(html_body)))
            hyip_hits = len(set(HYIP_REGEX.findall(html_body)))
            structure_hits = len(set(SCAM_STRUCTURE_REGEX.findall(html_body)))

            # check <title> — crypto + HYIP in the title is very high confidence
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html_body[:2000], re.DOTALL)
            title = title_match.group(1).strip() if title_match else ""
            title_confirmed = bool(title and CRYPTO_REGEX.search(title) and HYIP_REGEX.search(title))

            # confirmation: original rule, OR structural assist, OR title match
            confirmed = (
                (crypto_hits >= 1 and hyip_hits >= 2)
                or (crypto_hits >= 1 and hyip_hits >= 1 and structure_hits >= 1)
                or title_confirmed
            )

            if confirmed:
                print(f"[+] NEW SCAM CONFIRMED: {strict_url}")

                with write_lock:
                    active_threats.append(strict_url)
                    with open(OUTPUT_FILE, "a") as file:
                        file.write(f"{strict_url}\n")
                    seen_urls.add(strict_url)
                
    except requests.RequestException as e:
        print(f"[-] {strict_url}: {e}", flush=True)

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
