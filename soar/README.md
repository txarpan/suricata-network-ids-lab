# SOAR Auto-Response v2

Monitors Wazuh API for Suricata alerts and automatically blocks
attacker IPs via UFW — extending Project 1's SOAR script with
network-layer trigger support.

## Trigger Rules

| Rule ID | Attack | Action |
|---------|--------|--------|
| 200001 | TCP SYN Port Scan | Block source IP |
| 200003 | SSH Brute Force | Block source IP |
| 200004 | DNS Tunneling | Block source IP |
| 200005 | C2 HTTP Beaconing | Block source IP |
| 200007 | Lateral Movement | Block source IP |

## Usage

```bash
pip3 install requests
python3 auto-block-v2.py
```

## How It Works

1. Authenticates to Wazuh API via JWT
2. Polls for recent Suricata alerts every 30 seconds
3. Extracts source IP from EVE JSON alert data
4. Blocks attacker IP via UFW automatically
5. Tracks blocked IPs to avoid duplicate rules
