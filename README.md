# Zero-Day Threat Intel Sniper (Autonomous CT Monitor)

An autonomous, headless threat intelligence pipeline built for the Raspberry Pi. This project monitors the global Certificate Transparency (CT) network in real-time, filters zero-day domain registrations for cryptocurrency investment scams, and automatically verifies malicious infrastructure using daily cron jobs.

By running a local CertStream server natively, this architecture completely bypasses third-party rate limits, API bans, and Cloudflare blocks.

## Notes
1. **The Blog**: Check out the blog to see my progress, interesting finds, and new ideas!
2. **Log FIles**: I will try to upload the files I log for the day the day after I submit them to be flagged . So the log files for March 1st 2026 would be posted on March 2nd 2026 .

## Architecture Flow

1. **The Firehose (`certstream-server-go`):** Runs as a background `systemd` daemon, pulling raw SSL/TLS certificate registrations from public Certificate Transparency logs into the Pi's memory.
2. **The Live Sniper (`live_sniper.py`):** A Python WebSocket client running persistently in `tmux`. It connects to the local Firehose (127.0.0.1), applies strict intersection filtering to catch crypto-scam domains, and logs them dynamically by date. Auto-reconnects on disconnection — no manual restart needed.
3. **The Deep Verifier (`html_verifier.py`):** An automated Python scanner triggered by `cron` at 11:50 PM daily. It visits the day's suspect domains through a residential proxy, analyzes their raw HTML for specific scam footprints (HYIP templates, structural signals, title tags), and outputs verified, actionable targets.

## Prerequisites & Hardware
* **Hardware:** Raspberry Pi (Tested on ARM64/ARMv7) with a stable internet connection.
* **OS:** Debian/Raspberry Pi OS.
* **Dependencies:** Python 3.9+, `tmux`, `systemd`.
* **Proxy:** A residential proxy (e.g., Decodo/SmartProxy) with IP whitelisting for the HTML verifier.

---

## Installation & Deployment Guide

### Phase 1: Build the Local Server
Instead of relying on public APIs, we download and run the pre-compiled CertStream Go binary.

**1. Create the directory and download the binary:**
```bash
mkdir -p ~/go/bin/
wget -O ~/go/bin/certstream-server-go https://github.com/d-Rickyy-b/certstream-server-go/releases/download/v1.8.2/certstream-server-go_1.8.2_linux_arm64
chmod +x ~/go/bin/certstream-server-go
```

**2. Download the default configuration file:**

```bash
wget -O ~/go/bin/config.yaml https://raw.githubusercontent.com/d-Rickyy-b/certstream-server-go/master/config.sample.yaml
```


**3. Create the systemd background service:**

```
sudo nano /etc/systemd/system/certstream.service
```

**Paste the following:**

```
[Unit]
Description=CertStream God Mode Server
After=network.target

[Service]
Type=simple
User=%i
WorkingDirectory=/home/%i/go/bin/
Restart=always
RestartSec=5
ExecStart=/home/%i/go/bin/certstream-server-go

[Install]
WantedBy=multi-user.target
```

> **Note:** Replace `%i` with your actual Linux username (e.g., `pisniper`). Systemd does not expand `~` or `$USER`.

**4. Enable and start the firehose:**

```
sudo systemctl daemon-reload
sudo systemctl enable certstream
sudo systemctl start certstream
```

### Phase 2: Deploy the Python Pipeline

**1. Install Python requirements and Tmux:**

```bash
sudo apt update && sudo apt install tmux python3-pip python3-venv -y
cd ~/CertStream-CryptoScamMonitor
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**2. Configure the proxy:**

The HTML verifier routes all requests through a residential proxy to avoid exposing your Pi's IP to scam domains. Note: only `html_verifier.py` uses the proxy — `live_sniper.py` connects to the local CertStream server and does not require proxy configuration.

Copy the example and fill in your proxy details:

```bash
cp .env.example .env
nano .env
```

Set your proxy host and port (IP must be whitelisted on the provider's dashboard):

```
PROXY_HOST=gate.your-proxy-provider.com
PROXY_PORT=10001
```

Both Python scripts automatically detect your home directory using `Path.home()`, so no manual path editing is required.

### Phase 3: Autonomous Execution

**1. Launch the Live Sniper in tmux:**

```bash
source .venv/bin/activate
tmux new -s sniper
python3 scripts/live_sniper.py
```

The sniper will automatically reconnect if the CertStream server restarts. It also loads any existing targets from today's log on startup to avoid duplicates after a restart.

**Press Ctrl+B, then D to detach and leave it running in the background.**

**2. Automate the Deep Verifier:**

This command sets the verifier to run automatically at 11:50 PM every night to scan the day's catches.

```bash
crontab -e

# Add this line to the very bottom on a new line without a # in front of it
50 23 * * * $HOME/CertStream-CryptoScamMonitor/.venv/bin/python $HOME/CertStream-CryptoScamMonitor/scripts/html_verifier.py >> $HOME/scam_logs/verifier_cron.log 2>&1
```

> **Note:** `cron` expands `$HOME` automatically. Do not use `~` in crontab entries — it is not expanded by cron.

## Log Management

Your Raspberry Pi will now operate completely headless. Both scripts automatically create and write to `~/scam_logs/`. Check this directory daily for two files:

`targets_YYYY-MM-DD.txt`: The raw suspicious domains caught by the WebSocket.

`confirmed_YYYY-MM-DD.txt`: The verified, actively deployed scam infrastructure ready for wallet extraction.

## Disclaimer

**This tool is built strictly for OSINT, threat intelligence, and defensive cybersecurity research. Do not use this pipeline to target or interact with infrastructure you do not have explicit permission to investigate.**

## Contact
To contact me DM bigddoesstuff#1145 on discord
