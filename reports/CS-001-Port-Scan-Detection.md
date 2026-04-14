# CS-001 — TCP/UDP Port Scan Detection

## Executive Summary
On April 13, 2026, reconnaissance activity was detected originating from `192.168.0.161` (Kali Linux) targeting `192.168.0.133` (Ubuntu victim). Suricata IDS detected both TCP SYN and UDP port scanning activity using custom rules 200001 and 200002, mapped to MITRE ATT&CK technique T1046. Alerts were forwarded to Wazuh SIEM in real time.

---

## Attack Description
Port scanning is the first step in almost every attack. Before an attacker can exploit a target, they need to know what services are running and which ports are open. Tools like Nmap send packets to every port and analyze responses to build a picture of the target's attack surface.

- **TCP SYN Scan** (`nmap -sS`) — sends SYN packets without completing the handshake. Fast and stealthy. Identifies open TCP ports.
- **UDP Scan** (`nmap -sU`) — probes UDP ports for services like DNS, SNMP, DHCP. Slower but necessary for full reconnaissance.

Real-world usage: Every penetration tester and threat actor runs port scans before attacking. APT groups use custom scanners to avoid detection, but the underlying behavior — high volume of connection attempts across multiple ports — remains the same.

---

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Discovery |
| Technique | T1046 — Network Service Discovery |
| Platform | Linux, Windows |
| Data Source | Network Traffic |

---

## Attack Simulation

**Attacker machine:** Kali Linux — 192.168.0.161
**Target:** Ubuntu — 192.168.0.133

```bash
# TCP SYN Scan
nmap -sS 192.168.0.133

# UDP Scan
nmap -sU --top-ports 100 192.168.0.133
```

**Nmap output (TCP SYN scan):**

Host is up (0.00011s latency).
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp closed http

---

## Detection Evidence

### Suricata fast.log alerts
04/14/2026-04:34:15.002  [] [1:200001:1] CUSTOM TCP SYN Port Scan Detected []
[Classification: Detection of a Network Scan] [Priority: 3] {TCP}
192.168.0.161:62172 -> 192.168.0.133:139
04/13/2026-11:30:36.373107  [] [1:200002:1] CUSTOM UDP Port Scan Detected []
[Classification: Detection of a Network Scan] [Priority: 3] {UDP}
192.168.0.161:49814 -> 192.168.0.133:500

### Wazuh SIEM alert
- Rule ID: 86601
- Description: Suricata: Alert - CUSTOM TCP SYN Port Scan Detected
- Agent: ubuntu-lab-01 (192.168.0.133)
- Severity: Level 3

### Zeek conn.log evidence
Zeek recorded all connection attempts from Kali across multiple ports, confirming scanning behavior via high volume of short-duration connections with `conn_state: S0` (SYN sent, no response).

---

## Custom Rule Breakdown

### Rule 200001 — TCP SYN Scan
alert tcp any any -> $HOME_NET any (
msg:"CUSTOM TCP SYN Port Scan Detected";
flags:S;
threshold: type both, track by_src, count 20, seconds 10;
classtype:network-scan;
sid:200001;
rev:1;
metadata:mitre_technique T1046;
)

| Field | Explanation |
|-------|-------------|
| `alert tcp` | Match TCP traffic |
| `flags:S` | Only SYN packets — no ACK, no data |
| `threshold: count 20, seconds 10` | Fire only after 20 SYN packets in 10 seconds from same source |
| `track by_src` | Track per source IP |
| `classtype:network-scan` | Classification for reporting |

### Rule 200002 — UDP Scan
alert udp any any -> $HOME_NET any (
msg:"CUSTOM UDP Port Scan Detected";
threshold: type both, track by_src, count 20, seconds 10;
classtype:network-scan;
sid:200002;
rev:1;
metadata:mitre_technique T1046;
)

---

## Incident Response Steps

### 1. Triage
- Identify source IP: `192.168.0.161`
- Check scan scope: how many ports targeted, what services probed
- Determine if source is internal or external
- Check if source IP has prior alerts

### 2. Containment
- Block source IP at firewall level immediately
```bash
sudo ufw deny from 192.168.0.161
```
- Isolate target if compromise is suspected

### 3. Investigation
- Review Zeek conn.log for full connection history from attacker IP
- Check if any ports responded — indicates potential follow-up exploitation
- Correlate with authentication logs for login attempts post-scan

### 4. Remediation
- Keep firewall rules updated — close unnecessary ports
- Enable port knocking or VPN for sensitive services
- Review exposed services — remove anything not needed

---

## Screenshots

- `screenshots/p2-01-rule-200001-syn-scan.png` — Nmap SYN scan + Suricata alert
- `screenshots/p2-02-rule-200002-udp-scan.png` — Nmap UDP scan + Suricata alert
- `screenshots/p2-08-wazuh-dashboard-all-alerts.png` — Wazuh dashboard showing alert

---

## References
- [MITRE ATT&CK T1046](https://attack.mitre.org/techniques/T1046/)
- [Suricata Rule Documentation](https://suricata.readthedocs.io/en/latest/rules/)
- [Nmap Port Scanning Techniques](https://nmap.org/book/man-port-scanning-techniques.html)
