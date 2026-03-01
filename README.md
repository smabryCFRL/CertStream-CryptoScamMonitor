# Zero-Day Threat Intel Sniper (Autonomous CT Monitor)

An autonomous, headless threat intelligence pipeline built for the Raspberry Pi. This project monitors the global Certificate Transparency (CT) network in real-time, filters zero-day domain registrations for cryptocurrency investment scams, and automatically verifies malicious infrastructure using daily cron jobs.

By running a local CertStream server natively, this architecture completely bypasses third-party rate limits, API bans, and Cloudflare blocks.

## Architecture Flow

1. **The Firehose (`certstream-server-go`):** Runs as a background `systemd` daemon, independently pulling raw SSL/TLS certificate registrations from Google and Let's Encrypt directly into the Pi's memory.
2. **The Live Sniper (`live_sniper.py`):** A Python WebSocket client running persistently in `tmux`. It connects to the local Firehose (127.0.0.1), applies strict intersection filtering to catch crypto-scam domains, and logs them dynamically by date.
3. **The Deep Verifier (`html_verifier.py`):** An automated Python scanner triggered by `cron` at 11:50 PM daily. It visits the day's suspect domains, analyzes their raw HTML for specific scam footprints (HYIP templates, fake crypto wallets), and outputs verified, actionable targets.

## Prerequisites & Hardware
* **Hardware:** Raspberry Pi (Tested on ARM64/ARMv7) with a stable internet connection.
* **OS:** Debian/Raspberry Pi OS.
* **Dependencies:** Python 3, `tmux`, `systemd`.

---

## Installation & Deployment Guide

### Phase 1: Build the Local Server
Instead of relying on public APIs, we download and run the pre-compiled CertStream Go binary.

**1. Create the directory and download the binary:**
```
mkdir -p /home/lild/go/bin/
wget -O /home/lild/go/bin/certstream-server-go [https://github.com/d-Rickyy-b/certstream-server-go/releases/download/v1.8.2/certstream-server-go_1.8.2_linux_arm64](https://github.com/d-Rickyy-b/certstream-server-go/releases/download/v1.8.2/certstream-server-go_1.8.2_linux_arm64)
chmod +x /home/lild/go/bin/certstream-server-go
```

**2. Download the default configuration file:**

```
wget -O /home/lild/go/bin/config.yaml [https://raw.githubusercontent.com/d-Rickyy-b/certstream-server-go/master/config.sample.yaml](https://raw.githubusercontent.com/d-Rickyy-b/certstream-server-go/master/config.sample.yaml)
```


**3. Create the systemd background service:**

```
sudo nano /etc/systemd/system/certstream.service
```

**Paste the following: (change * to your local user name)**

```
[Unit]
Description=CertStream God Mode Server
After=network.target

[Service]
Type=simple
User=lild
WorkingDirectory=/home/*/go/bin/
Restart=always
RestartSec=5
ExecStart=/home/*/go/bin/certstream-server-go

[Install]
WantedBy=multi-user.target
```

**4. Enable and start the firehose:**

```
sudo systemctl daemon-reload
sudo systemctl enable certstream
sudo systemctl start certstream
```

### Phase 2: Deploy the Python Pipeline

**1. Install Python requirements and Tmux:**

```
sudo apt update && sudo apt install tmux python3-pip -y
pip3 install websocket-client requests --break-system-packages
```

**2. Create the data directory:**

#### This is where the automated scripts will save the daily target and confirmed scam lists (replace * with your local username)

```
mkdir /home/*/scam_logs
```

**3. Clone the repository and configure scripts:**

Look through the code for `live_sniper.py` and `html_verifier` for any configuration changes

**Phase 3: Autonomous Execution**

```
tmux new -s sniper
python3 live_sniper.py
```

**IMPORTANT**

When you want to detach the feed of all the domains being detected **only use this keystroke**

**Press Ctrl+B, then D to detach and leave it running in the background.**

**2. Automate the Deep Verifier:**

This command sets the verifier to run automatically at 11:50 PM every night to scan the day's catches.

```
crontab -e

# Add this line to the very bottom on a new line without a # in front of it
# replace * with your local username

50 23 * * * /usr/bin/python3 /home/*/html_verifier.py >> /home/*/scam_logs/verifier_cron.log 2>&1
```

## Log Management

Your Raspberry Pi will now operate completely headless. Check your /home/*/scam_logs/ directory daily for two files:

`targets_YYYY-MM-DD.txt`: The raw suspicious domains caught by the WebSocket.

`confirmed_YYYY-MM-DD.txt`: The verified, actively deployed scam infrastructure ready for wallet extraction.

## Disclaimer

**This tool is built strictly for OSINT, threat intelligence, and defensive cybersecurity research. Do not use this pipeline to target or interact with infrastructure you do not have explicit permission to investigate.**
