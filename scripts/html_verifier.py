import os
import sys
import requests
import urllib3
import datetime
import threading
import re
from pathlib import Path
from zoneinfo import ZoneInfo
from concurrent.futures import ThreadPoolExecutor, as_completed

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
LOG_DIR = Path.home() / "scam_logs"
LOG_DIR.mkdir(exist_ok=True)
today = datetime.datetime.now(tz=ZoneInfo("US/Central")).strftime("%Y-%m-%d")
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
consecutive_failures = 0
MAX_CONSECUTIVE_FAILURES = 50

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


def check_html_and_save(target):
    global consecutive_failures
    strict_url = normalize_url(target)
    if strict_url in seen_urls:
        return

    try:
        # stream=True defers body download; we read only the first chunk below and then stop
        response = requests.get(
            strict_url,
            timeout=(10, 15),
            verify=False,
            headers={"User-Agent": "Mozilla/5.0"},
            stream=True,
            proxies=PROXIES,
        )

        try:
            if response.status_code != 200:
                return

            # read only the first ~73 KB of HTML — usually enough to detect scam fingerprints
            html_body = ""
            for chunk in response.iter_content(chunk_size=75000):
                if chunk:
                    html_body = chunk.decode("utf-8", errors="ignore").lower()
                    break

            crypto_hits = len(set(CRYPTO_REGEX.findall(html_body)))
            hyip_hits = len(set(HYIP_REGEX.findall(html_body)))
            structure_hits = len(set(SCAM_STRUCTURE_REGEX.findall(html_body)))

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
        finally:
            response.close()

        consecutive_failures = 0

    except requests.RequestException as e:
        print(f"[-] {strict_url}: {e}", flush=True)
        consecutive_failures += 1
        if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
            print(
                f"[!!!] {MAX_CONSECUTIVE_FAILURES} consecutive failures — proxy may be down.",
                flush=True,
            )


if __name__ == "__main__":
    try:
        if not os.path.exists(INPUT_FILE):
            print(f"[-] No targets found for today ({INPUT_FILE}). Exiting.")
            exit()

        with open(INPUT_FILE, "r") as file:
            targets = [line.strip() for line in file if line.strip()]

        new_targets = [t for t in targets if normalize_url(t) not in seen_urls]

        print(f"[*] Loaded {len(seen_urls)} already confirmed scams.")
        print(f"[*] Scanning {len(new_targets)} NEW targets from today's log...\n")

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_html_and_save, t) for t in new_targets]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"[!!!] Worker thread crashed: {e}", flush=True)

        print(
            f"\n[+] Complete! Added {len(active_threats)} NEW scams to {OUTPUT_FILE}."
        )

        if len(new_targets) > 0:
            hit_rate = (len(active_threats) / len(new_targets)) * 100
            print(
                f"[*] Session Hit Rate: {hit_rate:.2f}% ({len(active_threats)}/{len(new_targets)} scanned)"
            )
        else:
            print("[*] Session Hit Rate: N/A (0 new targets scanned)")

    except KeyboardInterrupt:
        print("\n[*] Interrupted by user. Exiting.")
        sys.exit(0)
