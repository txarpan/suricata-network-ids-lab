#!/usr/bin/env python3
"""
SOAR Auto-Response v2 — Suricata + Wazuh Integration
Monitors Wazuh alerts.json for Suricata detections and
automatically blocks attacker IPs via UFW.

Author: Arpan Mukherjee
Project: Suricata Network IDS Lab
"""

import subprocess
import json
import time
from datetime import datetime

CONTAINER   = "single-node-wazuh.manager-1"
ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
CHECK_INTERVAL = 30
BLOCKED_IPS = set()

TRIGGER_RULES = {
    "200001": "TCP SYN Port Scan",
    "200003": "SSH Brute Force",
    "200004": "DNS Tunneling",
    "200005": "C2 HTTP Beaconing",
    "200007": "Lateral Movement SMB/RDP",
}

def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}")

def get_alerts():
    """Read last 50 lines from Wazuh alerts.json inside Docker container."""
    try:
        result = subprocess.run(
            ["docker", "exec", CONTAINER, "tail", "-50", ALERTS_FILE],
            capture_output=True, text=True
        )
        alerts = []
        for line in result.stdout.strip().split("\n"):
            try:
                alerts.append(json.loads(line))
            except Exception:
                continue
        return alerts
    except Exception as e:
        log(f"Error reading alerts: {e}")
        return []

def extract_attacker_ip(alert):
    """Extract source IP and Suricata signature ID from alert."""
    try:
        data = alert.get("data", {})
        src_ip = data.get("src_ip")
        sig_id = str(data.get("alert", {}).get("signature_id", ""))
        return src_ip, sig_id
    except Exception:
        return None, None

def block_ip(ip):
    """Block attacker IP via UFW on Ubuntu victim machine."""
    if ip in BLOCKED_IPS:
        return
    try:
        result = subprocess.run(
            ["ssh", "vboxuser@192.168.0.133", f"sudo ufw deny from {ip}"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            BLOCKED_IPS.add(ip)
            log(f"BLOCKED: {ip} via UFW on Ubuntu")
        else:
            log(f"UFW block failed for {ip}: {result.stderr}")
    except Exception as e:
        log(f"Block error: {e}")

def main():
    log("SOAR Auto-Response v2 starting...")
    log(f"Container: {CONTAINER}")
    log(f"Monitoring rules: {list(TRIGGER_RULES.keys())}")
    log(f"Poll interval: {CHECK_INTERVAL}s")
    print("-" * 60)

    while True:
        alerts = get_alerts()
        for alert in alerts:
            src_ip, sig_id = extract_attacker_ip(alert)
            if src_ip and sig_id in TRIGGER_RULES:
                rule_name = TRIGGER_RULES[sig_id]
                if src_ip not in BLOCKED_IPS:
                    log(f"ALERT: Rule {sig_id} ({rule_name}) — attacker: {src_ip}")
                    block_ip(src_ip)
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
