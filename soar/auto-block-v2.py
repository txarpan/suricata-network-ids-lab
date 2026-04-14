#!/usr/bin/env python3
"""
SOAR Auto-Response v2 — Suricata + Wazuh Integration
Monitors Wazuh API for Suricata alerts and automatically blocks
attacker IPs via UFW on the Ubuntu victim machine.

Author: Arpan Mukherjee
Project: Suricata Network IDS Lab
MITRE: T1059 (response automation)
"""

import requests
import subprocess
import json
import time
import urllib3
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
WAZUH_HOST = "https://192.168.0.224:55000"
WAZUH_USER = "wazuh"
WAZUH_PASS = "wazuh"
AGENT_ID   = "001"
CHECK_INTERVAL = 30  # seconds between API polls
BLOCKED_IPS = set()  # track already blocked IPs

# Suricata rule IDs to trigger auto-block
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

def get_token():
    """Authenticate to Wazuh API and return JWT token."""
    try:
        resp = requests.post(
            f"{WAZUH_HOST}/security/user/authenticate",
            auth=(WAZUH_USER, WAZUH_PASS),
            verify=False,
            timeout=10
        )
        if resp.status_code == 200:
            token = resp.json()["data"]["token"]
            log("Authenticated to Wazuh API successfully")
            return token
        else:
            log(f"Auth failed: {resp.status_code}")
            return None
    except Exception as e:
        log(f"Auth error: {e}")
        return None

def get_recent_alerts(token):
    """Fetch recent Suricata alerts from Wazuh API."""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(
            f"{WAZUH_HOST}/alerts",
            headers=headers,
            params={
                "agent_ids": AGENT_ID,
                "limit": 50,
                "sort": "-timestamp"
            },
            verify=False,
            timeout=10
        )
        if resp.status_code == 200:
            return resp.json().get("data", {}).get("affected_items", [])
        else:
            log(f"Alert fetch failed: {resp.status_code}")
            return []
    except Exception as e:
        log(f"Alert fetch error: {e}")
        return []

def extract_attacker_ip(alert):
    """Extract source IP from Suricata EVE JSON alert."""
    try:
        data = alert.get("data", {})
        src_ip = data.get("src_ip")
        rule_id = data.get("alert", {}).get("signature_id", "")
        return src_ip, str(rule_id)
    except Exception:
        return None, None

def block_ip(ip):
    """Block attacker IP via UFW."""
    if ip in BLOCKED_IPS:
        return
    try:
        result = subprocess.run(
            ["sudo", "ufw", "deny", "from", ip],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            BLOCKED_IPS.add(ip)
            log(f"BLOCKED: {ip} via UFW")
        else:
            log(f"UFW block failed for {ip}: {result.stderr}")
    except Exception as e:
        log(f"Block error for {ip}: {e}")

def main():
    log("SOAR Auto-Response v2 starting...")
    log(f"Monitoring rules: {list(TRIGGER_RULES.keys())}")
    log(f"Poll interval: {CHECK_INTERVAL}s")
    print("-" * 60)

    token = get_token()
    if not token:
        log("Failed to authenticate. Exiting.")
        return

    while True:
        alerts = get_recent_alerts(token)
        for alert in alerts:
            src_ip, rule_id = extract_attacker_ip(alert)
            if src_ip and rule_id in TRIGGER_RULES:
                rule_name = TRIGGER_RULES[rule_id]
                if src_ip not in BLOCKED_IPS:
                    log(f"ALERT: Rule {rule_id} ({rule_name}) — attacker IP: {src_ip}")
                    block_ip(src_ip)
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
