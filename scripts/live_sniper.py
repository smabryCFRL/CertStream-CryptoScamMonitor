import websocket
import json
import os
import datetime

# Pointing to the Go server running on this Pi
CERTSTREAM_URL = "ws://127.0.0.1:8080/" 

# Create your own keywords here !
# CRYPTO_BASE - keywords that have something to do with crypto
# ACTION_BASE - keywords that are a verb that attempt to make the victim feel as if their money will be doing something
# TRUST_BASE - keywords that attempt to make the victim trust the cite by seeming more legitimate
# HIGH_RISK_TLDS - Top level domains (.com) that crytpo scam sites often use
CRYPTO_BASE = ['crypto', 'btc']
ACTION_BASE = ['invest', 'earn']
TRUST_BASE = ['legit', 'elite']
HIGH_RISK_TLDS = ['.top', '.vip']

cert_count = 0
seen_urls = set()

def is_highly_suspicious(domain):
    has_crypto = any(word in domain for word in CRYPTO_BASE)
    has_action = any(word in domain for word in ACTION_BASE)
    has_trust  = any(word in domain for word in TRUST_BASE)

    # Keyword scoring by crypto, action, trust and TLD
    # 1 crypto and 1 action = TRUE
    # 1 trust and 1 crypto = TRUE
    # 1 tld and 1 crypto or action or trust = TRUE
    # Return everything else as to not waste time on sites that arent what we are looking for
    # Feel free to adjust this to get more or less output
    if (has_crypto and has_action) or (has_trust and has_action): return True
    if any(domain.endswith(tld) for tld in HIGH_RISK_TLDS) and (has_crypto or has_action or has_trust): return True
    return False

def on_message(ws, message):
    global cert_count
    try:
        data = json.loads(message)
        if data.get('message_type') != "certificate_update": 
            return
            
        cert_count += 1
        if cert_count % 100 == 0: print(".", end="", flush=True) # Helps to let you know that the script is running correctly by printing dots every 100 certs
            
        for domain in data['data']['leaf_cert']['all_domains']:
            clean_domain = domain.replace('*.', '').lower()
            
            if is_highly_suspicious(clean_domain):
                strict_url = f"https://{clean_domain}/" # Create a submittable link
                if strict_url in seen_urls: continue
                seen_urls.add(strict_url)
                
                today = datetime.datetime.now().strftime("%Y-%m-%d") # Get the date for today before making the file
                daily_filename = f"/home/*/scam_logs/targets_{today}.txt" # Replace * with your local Pi's username
                
                print(f"\n[*] Target Locked: {strict_url} -> Saving to {daily_filename}")
                with open(daily_filename, "a") as file:
                    file.write(f"{strict_url}\n")
                    
    except Exception: pass 

def on_error(ws, error): print(f"\n[-] ERROR: {error}")
def on_close(ws, close_status_code, close_msg): print("\n[-] Connection closed.")
def on_open(ws): print(f"\n[+] Connected directly to local Pi Firehose loopback!\n")

if __name__ == "__main__":
    print("[*] Starting Autonomous Pi Sniper...")
    ws = websocket.WebSocketApp(CERTSTREAM_URL, on_open=on_open, on_message=on_message, on_error=on_error, on_close=on_close)
    ws.run_forever()
