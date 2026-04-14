# CS-002 — DNS Tunneling Detection & Analysis

> **Note:** This simulation replicates the query frequency pattern of DNS tunneling. Full tunneling payload simulation requires tools like iodine or dnscat2, which require a controlled external domain. The detection rule targets the volume anomaly, which is the primary indicator in real SOC environments.

## Executive Summary
On April 13, 2026, anomalous DNS query activity was detected originating from `192.168.0.161` (Kali Linux). Suricata IDS flagged an abnormally high DNS query rate — 50+ queries in 10 seconds — using custom rule 200004, mapped to MITRE ATT&CK technique T1071.004. This pattern is consistent with DNS tunneling, a technique used by attackers to exfiltrate data or establish C2 channels over DNS — a protocol rarely blocked by firewalls.

---

## Attack Description
DNS tunneling abuses the DNS protocol to encode data inside DNS queries and responses. Since DNS traffic is almost never blocked at the network perimeter, attackers use it to:
- **Exfiltrate data** — encode stolen files inside DNS queries sent to an attacker-controlled domain
- **Establish C2 channels** — receive commands from a C2 server via DNS responses
- **Bypass firewalls** — even air-gapped networks often allow DNS traffic

**How it works:**
1. Attacker controls a domain (e.g., `evil.com`) and its DNS server
2. Malware on victim encodes data into subdomains: `encoded-data.evil.com`
3. DNS query goes to attacker's server — attacker decodes the data
4. Response contains encoded commands back to the malware

**Detection challenge:** Individual DNS queries look normal. The attack is only visible at the volume and frequency level — which is exactly what our threshold-based rule catches.

Real-world examples: DNScat2, iodine, and Cobalt Strike all support DNS tunneling. APT groups like APT32 have used DNS tunneling extensively for long-term persistence.

---

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Technique | T1071 — Application Layer Protocol |
| Sub-technique | T1071.004 — DNS |
| Platform | Linux, Windows, macOS |
| Data Source | Network Traffic, DNS logs |

---

## Attack Simulation

**Attacker machine:** Kali Linux — 192.168.0.161
**DNS Server:** 192.168.0.1 (router)

```bash
# Simulate high-rate DNS queries mimicking tunneling behavior
for i in $(seq 1 100); do dig @192.168.0.1 test$i.google.com; done
```

This generates 100 DNS queries in rapid succession — mimicking the query frequency pattern of DNS tunneling tools.

---

## Detection Evidence

### Suricata fast.log alert
04/13/2026-11:40:14.996164  [] [1:200004:1] CUSTOM DNS Tunneling - High Query Rate []
[Classification: Potential Corporate Privacy Violation] [Priority: 1] {UDP}
192.168.0.161:58502 -> 192.168.0.1:53

**Key indicators:**
- Priority 1 — highest severity
- Classification: Potential Corporate Privacy Violation
- Source: Kali (192.168.0.161) → DNS server port 53
- Protocol: UDP (standard DNS transport)

### Wazuh SIEM alert
- Rule ID: 86601
- Description: Suricata: Alert - CUSTOM DNS Tunneling - High Query Rate
- Agent: ubuntu-lab-01 (192.168.0.133)
- MITRE tag: T1071.004

### Zeek dns.log evidence
Zeek captured all DNS queries in structured JSON format.
Key fields logged per query: timestamp, source IP, destination IP,
query name, record type, response code.

---

## Custom Rule Breakdown

### Rule 200004 — DNS Tunneling
alert dns any any -> any 53 (
msg:"CUSTOM DNS Tunneling - High Query Rate";
threshold: type both, track by_src, count 50, seconds 10;
classtype:policy-violation;
sid:200004;
rev:1;
metadata:mitre_technique T1071.004;
)

| Field | Explanation |
|-------|-------------|
| `alert dns` | Match DNS protocol traffic specifically |
| `any any -> any 53` | Any source to any DNS server on port 53 |
| `threshold: count 50, seconds 10` | Fire after 50+ DNS queries in 10 seconds from same source |
| `track by_src` | Track per source IP |
| `classtype:policy-violation` | Flags as policy violation for SOC triage |

**Why threshold-based detection works here:**
Normal DNS usage — browsing websites — generates roughly 1-5 queries per second at peak. DNS tunneling tools generate 50-500 queries per second. The threshold catches the anomaly without flagging legitimate traffic.

---

## Incident Response Steps

### 1. Triage
- Identify source IP making high-rate DNS queries: `192.168.0.161`
- Check query destinations — internal DNS server or external?
- Inspect Zeek dns.log for query patterns — random subdomains indicate tunneling
- Check query record types — TXT and NULL records are commonly used for tunneling

```bash
# Check Zeek dns.log for suspicious patterns
cat /opt/zeek/logs/current/dns.log | python3 -m json.tool | grep "192.168.0.161"
```

### 2. Containment
- Block source IP immediately
```bash
sudo ufw deny from 192.168.0.161
```
- Block outbound DNS to external servers — force all DNS through internal server only
- Rate-limit DNS queries at the firewall level

### 3. Investigation
- Decode captured DNS queries — look for base64 or hex-encoded payloads in subdomains
- Check if any data exfiltration occurred — volume of outbound DNS traffic
- Identify which process on the source machine was generating queries
- Review full timeline in Wazuh for related alerts

### 4. Remediation
- Implement DNS query rate limiting on DNS server
- Deploy DNS filtering solution (Pi-hole, Cisco Umbrella)
- Monitor for long or randomly-generated subdomain names
- Block DNS-over-HTTPS (DoH) to prevent bypassing DNS monitoring

---

## Screenshots

- `screenshots/p2-04-rule-200004-dns-tunneling.png` — DNS flood simulation + Suricata alert
- `screenshots/p2-08-wazuh-dashboard-all-alerts.png` — Wazuh dashboard showing alert
- `screenshots/p2-04b-zeek-dns-log-evidence.png` — Zeek dns.log JSON evidence

---

## References
- [MITRE ATT&CK T1071.004](https://attack.mitre.org/techniques/T1071/004/)
- [Detecting DNS Tunneling — SANS](https://www.sans.org/reading-room/whitepapers/dns/)
- [Zeek DNS Log Documentation](https://docs.zeek.org/en/master/scripts/base/protocols/dns/)
