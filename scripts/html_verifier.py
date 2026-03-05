import os
import sys
import socket
import requests
import datetime
import threading
import re
from pathlib import Path
from zoneinfo import ZoneInfo
from concurrent.futures import ThreadPoolExecutor, as_completed

from dotenv import load_dotenv

# load .env from project root (one level up from scripts/)
_env_file = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(_env_file)

# Decodo Web Scraping API (dashboard → Scraper tab → Basic auth token)
SCRAPER_TOKEN = os.getenv("SCRAPER_TOKEN", "")

if not SCRAPER_TOKEN:
    print("[-] SCRAPER_TOKEN must be set in .env. Exiting.")
    sys.exit(1)

SCRAPER_API = "https://scraper-api.decodo.com/v2/scrape"
SCRAPER_HEADERS = {
    "accept": "application/json",
    "content-type": "application/json",
    "authorization": f"Basic {SCRAPER_TOKEN}",
}
print("[+] Decodo Scraping API configured.")

# daily logging - makes a new file every day
# optional: pass a date like `python html_verifier.py 2026-03-04` to scan a specific day
LOG_DIR = Path.home() / "scam_logs"
LOG_DIR.mkdir(exist_ok=True)
today = (
    sys.argv[1]
    if len(sys.argv) > 1
    else datetime.datetime.now(tz=ZoneInfo("US/Central")).strftime("%Y-%m-%d")
)
INPUT_FILE = LOG_DIR / f"targets_{today}.txt"
OUTPUT_FILE = LOG_DIR / f"confirmed_{today}.txt"

# using Regex is better than for loops for keyword detection in most cases
# since it compiles to C and runs in O(n) time - \b ensures we only match whole words
CRYPTO_REGEX = re.compile(
    r"\b(bitcoin|btc|ethereum|eth|usdt|tether|bnb|trx|tron|solana|litecoin|dogecoin|crypto|blockchain|mining|staking|defi|web3|wallet|token|hash|miner)\b"
)
HYIP_REGEX = re.compile(
    r"\b(daily\s+roi|investment\s+plan|guaranteed\s+profit|passive\s+income|earn\s+daily|referral\s+bonus|minimum\s+deposit|instant\s+withdrawal|compound\s+interest|high\s+yield|roi\s+calculator|deposit\s+now|start\s+earning|join\s+now\s+and\s+earn|guaranteed\s+return|forex\s+trading|copy\s+trading|auto\s+trading)\b"
)

# structural signals — HYIP template DNA detectable from raw HTML
SCAM_STRUCTURE_REGEX = re.compile(
    r'(class=["\'](?:plan-card|pricing-table|investment-box|deposit-form)["\']'
    r"|<select[^>]*(?:coin|currency|crypto)[^>]*>"
    r"|<input[^>]*(?:deposit|invest|amount)[^>]*>"
    r"|\b(?:200%|300%|500%|1000%)\s*(?:roi|return|profit)"
    r"|(?:telegram|t\.me/)\w+"
    r"|<marquee\b"
    r")",
    re.IGNORECASE,
)

active_threats = []
seen_urls = set()
write_lock = threading.Lock()
sites_reached = 0
sites_alive = 0
api_errors = 0
empty_html = 0
js_shell_only = 0
has_crypto = 0
has_hyip = 0
has_structure = 0
near_misses = []

# preload files into memory to avoid re-reading the same file multiple times during execution
if os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, "r") as f:
        for line in f:
            url = line.strip()
            if url:
                seen_urls.add(url)


def normalize_url(target):
    """Strip scheme and trailing slashes, rebuild as https://domain/"""
    base = target.split("//")[-1].rstrip("/") if "://" in target else target.rstrip("/")
    return f"https://{base}/"


def extract_host(url):
    """Pull the hostname out of a URL."""
    return url.split("//")[-1].split("/")[0].split(":")[0]


def is_host_alive(host, port=443, timeout=3):
    """Quick TCP connect to check if anything is listening — no HTTP, no proxy cost."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, OSError):
        return False


JS_SHELL_INDICATORS = re.compile(
    r"(loading\.\.\.|加载中|<noscript>|__next_f|__nuxt|react-root|ng-app|app-root)",
    re.IGNORECASE,
)


def check_html_and_save(target):
    global sites_reached, sites_alive, api_errors, empty_html, js_shell_only
    global has_crypto, has_hyip, has_structure
    strict_url = normalize_url(target)
    if strict_url in seen_urls:
        return

    host = extract_host(strict_url)

    # Phase 1: free TCP liveness check — skip dead domains before spending API credits
    if not is_host_alive(host):
        return

    sites_alive += 1

    # Phase 2: fetch HTML via Decodo Scraping API (handles Cloudflare, anti-bot, JS)
    try:
        response = requests.post(
            SCRAPER_API,
            json={"url": strict_url},
            headers=SCRAPER_HEADERS,
            timeout=60,
        )

        sites_reached += 1

        if response.status_code != 200:
            api_errors += 1
            return

        data = response.json()
        results = data.get("results", [])
        if not results:
            empty_html += 1
            return

        html_body = results[0].get("content", "").lower()
        if not html_body or len(html_body) < 200:
            empty_html += 1
            return

        # detect JS-only shells (SPA sites that need rendering)
        visible_text = re.sub(r"<script[^>]*>.*?</script>", "", html_body, flags=re.DOTALL)
        visible_text = re.sub(r"<[^>]+>", "", visible_text).strip()
        if len(visible_text) < 100 and JS_SHELL_INDICATORS.search(html_body):
            js_shell_only += 1
            return

        crypto_hits = len(set(CRYPTO_REGEX.findall(html_body)))
        hyip_hits = len(set(HYIP_REGEX.findall(html_body)))
        structure_hits = len(set(SCAM_STRUCTURE_REGEX.findall(html_body)))

        if crypto_hits:
            has_crypto += 1
        if hyip_hits:
            has_hyip += 1
        if structure_hits:
            has_structure += 1

        # check <title> — crypto + HYIP in the title is very high confidence
        title_match = re.search(
            r"<title[^>]*>(.*?)</title>", html_body[:2000], re.DOTALL
        )
        title = title_match.group(1).strip() if title_match else ""
        title_confirmed = bool(
            title and CRYPTO_REGEX.search(title) and HYIP_REGEX.search(title)
        )

        # confirmation: original rule, OR structural assist, OR title match
        confirmed = (
            (crypto_hits >= 1 and hyip_hits >= 2)
            or (crypto_hits >= 1 and hyip_hits >= 1 and structure_hits >= 1)
            or title_confirmed
        )

        if confirmed:
            print(f"[+] NEW SCAM CONFIRMED: {strict_url}")

            with write_lock:
                with open(OUTPUT_FILE, "a") as file:
                    file.write(f"{strict_url}\n")
                active_threats.append(strict_url)
                seen_urls.add(strict_url)
        elif crypto_hits >= 1 or hyip_hits >= 1:
            with write_lock:
                near_misses.append(
                    f"  {strict_url} (crypto={crypto_hits} hyip={hyip_hits} struct={structure_hits})"
                )

    except requests.RequestException as e:
        print(f"[-] {strict_url}: {e}", flush=True)


if __name__ == "__main__":
    try:
        if not os.path.exists(INPUT_FILE):
            print(f"[-] No targets found for today ({INPUT_FILE}). Exiting.")
            exit()

        with open(INPUT_FILE, "r") as file:
            targets = [line.strip() for line in file if line.strip()]

        new_targets = [t for t in targets if normalize_url(t) not in seen_urls]

        print(f"[*] Loaded {len(seen_urls)} already confirmed scams.")
        print(f"[*] Scanning {len(new_targets)} NEW targets from {today} log...\n")

        # Phase 1: TCP liveness filter (fast, free, 50 threads)
        print("[*] Phase 1: TCP liveness check...")
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_html_and_save, t) for t in new_targets]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"[!!!] Worker thread crashed: {e}", flush=True)

        dead = len(new_targets) - sites_alive
        analyzed = sites_reached - api_errors - empty_html - js_shell_only

        print(f"\n{'='*50}")
        print(f"  SCAN RESULTS — {today}")
        print(f"{'='*50}")
        print(f"  Total targets:     {len(new_targets)}")
        print(f"  TCP alive:         {sites_alive}")
        print(f"  TCP dead:          {dead}")
        print(f"{'='*50}")
        print(f"  API calls made:    {sites_reached}")
        print(f"  API errors (4xx):  {api_errors}")
        print(f"  Empty/no HTML:     {empty_html}")
        print(f"  JS shell only:     {js_shell_only}")
        print(f"  Fully analyzed:    {analyzed}")
        print(f"{'='*50}")
        print(f"  Had crypto keywords: {has_crypto}")
        print(f"  Had HYIP phrases:    {has_hyip}")
        print(f"  Had structure sigs:  {has_structure}")
        print(f"  CONFIRMED SCAMS:     {len(active_threats)}")
        print(f"{'='*50}")

        if analyzed > 0:
            hit_rate = (len(active_threats) / analyzed) * 100
            print(f"  Hit Rate (of analyzed): {hit_rate:.2f}% ({len(active_threats)}/{analyzed})")
        else:
            print("  Hit Rate: N/A (0 sites analyzed)")

        if near_misses:
            print(f"\n[*] Near misses ({len(near_misses)} sites had partial matches):")
            for nm in near_misses[:20]:
                print(nm)
            if len(near_misses) > 20:
                print(f"  ... and {len(near_misses) - 20} more")

        print(f"\n[+] Output: {OUTPUT_FILE}")

    except KeyboardInterrupt:
        print("\n[*] Interrupted by user. Exiting.")
        sys.exit(0)
