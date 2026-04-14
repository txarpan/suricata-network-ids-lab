# CS-003 — C2 HTTP Beaconing Detection

## Executive Summary
On April 13, 2026, repetitive HTTP requests to a `/beacon` endpoint were detected originating from `192.168.0.161` (Kali Linux) targeting `192.168.0.133` (Ubuntu victim). Suricata IDS identified the beaconing pattern using custom rule 200005, mapped to MITRE ATT&CK technique T1071.001. The alert was classified as trojan activity — Priority 1 — and forwarded to Wazuh SIEM in real time.

---

## Attack Description
After malware infects a machine, it needs to maintain communication with the attacker's Command and Control (C2) server to receive instructions. This check-in process is called **beaconing**.

Malware uses HTTP beaconing because:
- HTTP traffic is allowed through almost every firewall
- It blends in with normal web browsing traffic
- Responses can carry encrypted commands

**How it works:**
1. Malware is deployed on victim machine
2. At regular intervals, malware sends HTTP GET request to attacker's server — e.g., `GET /beacon`
3. Attacker's server responds with encoded commands
4. Malware executes commands, sends results back via next beacon

**Detection challenge:** A single HTTP request looks completely normal. The pattern — same source, same URI, repeated at regular intervals — is what exposes the beaconing behavior.

Real-world examples: Cobalt Strike, Metasploit Meterpreter, and most RATs use HTTP/HTTPS beaconing. The interval is often configurable — slow beaconing (every 30 minutes) is harder to detect than fast beaconing.

---

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Technique | T1071 — Application Layer Protocol |
| Sub-technique | T1071.001 — Web Protocols |
| Platform | Linux, Windows, macOS |
| Data Source | Network Traffic, HTTP logs |

---

## Attack Simulation

**Attacker machine:** Kali Linux — 192.168.0.161
**Target:** Ubuntu — 192.168.0.133

```bash
# Start HTTP server on Ubuntu to simulate C2 server
mkdir -p /tmp/beacon-sim && echo "OK" > /tmp/beacon-sim/beacon
sudo python3 -m http.server 80

# Simulate C2 beaconing from Kali
for i in $(seq 1 20); do curl -s http://192.168.0.133/beacon; done
```

This simulates malware repeatedly calling home to a C2 server via HTTP GET requests to `/beacon`.

---

## Detection Evidence

### Suricata fast.log alert
04/13/2026-11:54:08.927267  [] [1:200005:1] CUSTOM C2 HTTP Beaconing Detected []
[Classification: A Network Trojan was detected] [Priority: 1] {TCP}
192.168.0.161:59084 -> 192.168.0.133:80

**Key indicators:**
- Priority 1 — highest severity
- Classification: A Network Trojan was detected
- Source: Kali (192.168.0.161) → Ubuntu port 80
- Protocol: TCP/HTTP

### Wazuh SIEM alert
- Rule ID: 86601
- Description: Suricata: Alert - CUSTOM C2 HTTP Beaconing Detected
- Agent: ubuntu-lab-01 (192.168.0.133)
- MITRE tag: T1071.001

### Zeek http.log evidence
Zeek http.log recorded every HTTP transaction — method, URI, response code, user agent — providing full forensic context for each beacon request beyond what Suricata's alert alone captures.

```bash
# Query Zeek http.log for beacon requests
sudo head -1 /opt/zeek/logs/current/http.log | python3 -m json.tool
```

---

## Custom Rule Breakdown

### Rule 200005 — C2 HTTP Beaconing
alert http any any -> any any (
msg:"CUSTOM C2 HTTP Beaconing Detected";
http.uri;
content:"/beacon";
threshold: type both, track by_src, count 5, seconds 60;
classtype:trojan-activity;
sid:200005;
rev:1;
metadata:mitre_technique T1071.001;
)

| Field | Explanation |
|-------|-------------|
| `alert http` | Match HTTP application layer traffic |
| `http.uri` | Inspect the URI field of HTTP requests |
| `content:"/beacon"` | Match requests containing /beacon in the URI |
| `threshold: count 5, seconds 60` | Fire after 5+ hits to /beacon in 60 seconds |
| `track by_src` | Track per source IP |
| `classtype:trojan-activity` | Highest risk classification |

---

## Incident Response Steps

### 1. Triage
- Identify source IP making repeated beacon requests: `192.168.0.161`
- Check Zeek http.log for full URI, user agent, and response details
- Determine beacon interval — faster intervals indicate active C2 session
- Check if destination is internal or external

### 2. Containment
- Block source IP immediately
```bash
sudo ufw deny from 192.168.0.161
```
- Block outbound HTTP to suspicious destinations at firewall
- Isolate infected host from network if internal machine is beaconing out

### 3. Investigation
- Identify the process making HTTP requests on source machine
- Check for persistence mechanisms — cron jobs, systemd services
- Review full HTTP session — what did the C2 server respond with?
- Search for lateral movement from infected host

### 4. Remediation
- Implement application layer firewall rules — whitelist known good domains
- Deploy proxy with SSL inspection to catch HTTPS beaconing
- Monitor for regular interval HTTP connections — jitter analysis
- Implement endpoint detection to catch the malware process itself

---

## Screenshots

- `screenshots/p2-05-rule-200005-c2-beaconing.png` — Curl beaconing simulation + Suricata alert
- `screenshots/p2-08-wazuh-dashboard-all-alerts.png` — Wazuh dashboard showing alert

---

## References
- [MITRE ATT&CK T1071.001](https://attack.mitre.org/techniques/T1071/001/)
- [Detecting C2 Beaconing — SANS](https://www.sans.org/reading-room/whitepapers/detection/)
- [Zeek HTTP Log Documentation](https://docs.zeek.org/en/master/scripts/base/protocols/http/)
