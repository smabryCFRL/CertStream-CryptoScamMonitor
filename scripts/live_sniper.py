import websocket
import json
import datetime
import time
import re

# pointing at the server running certstream firehose
CERTSTREAM_URL = "ws://127.0.0.1:8080/"


# using Regex is better than for loopsfor keyword detection in most cases
# since it compiles to C and runs in 0(n) time
CRYPTO_REGEX = re.compile(r'(crypto)')
ACTION_REGEX = re.compile(r'(invest)')
TRUST_REGEX  = re.compile(r'(legit)')

# tuples are better than lists and the .endswith() method accepts tuples
HIGH_RISK_TLDS = ('.top')

cert_count = 0
seen_urls = set()

def is_highly_suspicious(domain):
    is_high_risk = domain.endswith(HIGH_RISK_TLDS)
    has_crypto = bool(CRYPTO_REGEX.search(domain))
    has_action = bool(ACTION_REGEX.search(domain))
    
    # lets check to see if these return anything before we waste CPU cycles on has_trust
    # it has a lower importance level IMO
    if has_crypto and has_action:
        return True
        
    has_trust = bool(TRUST_REGEX.search(domain))
    
    if has_trust and has_action:
        return True
    if is_high_risk and (has_crypto or has_action or has_trust):
        return True
        
    return False

def on_message(ws, message):
    global cert_count
    try:
        data = json.loads(message)
        if data.get('message_type') != "certificate_update": return
            
        cert_count += 1
        if cert_count % 500 == 0: print(".", end="", flush=True)
            
        for domain in data['data']['leaf_cert']['all_domains']:
            clean_domain = domain.replace('*.', '').lower()
            
            if is_highly_suspicious(clean_domain):
                strict_url = f"https://{clean_domain}/"
                
                if strict_url in seen_urls: continue
                seen_urls.add(strict_url)
                
                today = datetime.datetime.now().strftime("%Y-%m-%d")
                # replace * with your local username
                daily_filename = f"/home/*/scam_logs/targets_{today}.txt"
                
                print(f"\n[*] Target Locked: {strict_url}")
                with open(daily_filename, "a") as file:
                    file.write(f"{strict_url}\n")
                    
        # zzz
        time.sleep(0.001) 
    except Exception: pass

def on_error(ws, error): print(f"\n[-] ERROR: {error}")
def on_close(ws, close_status_code, close_msg): print("\n[-] Connection closed.")
def on_open(ws): print(f"\n[+] Connected directly to local Pi Firehose loopback!\n")

if __name__ == "__main__":
    print("[*] Starting Autonomous Pi Sniper ...")
    ws = websocket.WebSocketApp(CERTSTREAM_URL, on_open=on_open, on_message=on_message, on_error=on_error, on_close=on_close)
    ws.run_forever()
