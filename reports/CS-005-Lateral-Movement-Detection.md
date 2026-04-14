# CS-005 — Lateral Movement Detection (SMB/RDP Scanning)

## Executive Summary
On April 13, 2026, internal network scanning targeting SMB (port 445) and RDP (port 3389) was detected originating from `192.168.0.161` (Kali Linux). Suricata IDS fired custom rule 200007, mapped to MITRE ATT&CK technique T1021. This behavior is consistent with post-compromise lateral movement — an attacker who has gained a foothold scanning internally for additional targets to compromise.

---

## Attack Description
Lateral movement is what happens **after** an attacker gets into a network. The goal shifts from gaining initial access to spreading across the network — compromising more machines, escalating privileges, and reaching high-value targets like domain controllers or file servers.

**Why SMB and RDP:**
- **SMB (port 445)** — Windows file sharing protocol. Exploitable via EternalBlue (MS17-010), used by WannaCry and NotPetya. Also used for pass-the-hash attacks.
- **RDP (port 3389)** — Remote Desktop Protocol. Provides full graphical access to Windows machines. Commonly brute-forced or exploited for lateral movement.

**Attack stages:**
1. Attacker compromises initial machine (beachhead)
2. Runs internal port scan to discover other hosts
3. Identifies machines with SMB/RDP open
4. Exploits vulnerabilities or uses stolen credentials to move laterally
5. Repeats until reaching target — domain controller, file server, database

**Why this is dangerous:** Lateral movement happens entirely inside the network — traditional perimeter defenses don't catch it. Only internal network monitoring tools like Suricata and Zeek can detect it.

---

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Lateral Movement |
| Technique | T1021 — Remote Services |
| Sub-techniques | T1021.001 (RDP), T1021.002 (SMB) |
| Platform | Windows, Linux |
| Data Source | Network Traffic, Process logs |

---

## Attack Simulation

**Attacker machine:** Kali Linux — 192.168.0.161
**Targets:** 192.168.0.133, 192.168.0.224, 192.168.0.1

```bash
# Simulate internal SMB/RDP reconnaissance
nmap -sS -p 445,3389 192.168.0.133 192.168.0.224 192.168.0.1
```

This simulates an attacker scanning the internal network for machines with SMB and RDP exposed — the first step of lateral movement.

---

## Detection Evidence

### Suricata fast.log alert
04/13/2026-11:59:51.961373  [] [1:200007:1] CUSTOM Lateral Movement - SMB/RDP Scan Detected []
[Classification: Detection of a Network Scan] [Priority: 3] {TCP}
192.168.0.161:44175 -> 192.168.0.133:3389
04/13/2026-11:59:55.678517  [] [1:200001:1] CUSTOM TCP SYN Port Scan Detected []
[Classification: Detection of a Network Scan] [Priority: 3] {TCP}
192.168.0.161:38829 -> 192.168.0.133:3389

**Key indicators:**
- Destination ports: 445 (SMB) and 3389 (RDP) — high-value lateral movement ports
- Source scanning multiple internal hosts — internal reconnaissance pattern
- Triggered alongside rule 200001 — confirms broader scanning activity

### Wazuh SIEM alert
- Rule ID: 86601
- Description: Suricata: Alert - CUSTOM Lateral Movement - SMB/RDP Scan Detected
- Agent: ubuntu-lab-01 (192.168.0.133)
- MITRE tag: T1021

### Zeek conn.log evidence
Zeek conn.log recorded all connection attempts to ports 445 and 3389 across multiple internal hosts — providing a complete map of the attacker's internal reconnaissance activity.

```bash
# Query Zeek conn.log for SMB/RDP connection attempts
sudo grep -h "" /opt/zeek/logs/current/conn.log | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        r = json.loads(line)
        if r.get('id.resp_p') in [445, 3389]:
            print(r)
    except: pass
" | head -5
```

---

## Custom Rule Breakdown

### Rule 200007 — Lateral Movement SMB/RDP Scan
alert tcp any any -> $HOME_NET [445,3389] (
msg:"CUSTOM Lateral Movement - SMB/RDP Scan Detected";
flags:S;
threshold: type both, track by_src, count 5, seconds 60;
classtype:network-scan;
sid:200007;
rev:1;
metadata:mitre_technique T1021;
)

| Field | Explanation |
|-------|-------------|
| `-> $HOME_NET [445,3389]` | Traffic targeting SMB or RDP ports on internal network |
| `flags:S` | SYN packets — connection attempts only |
| `threshold: count 5, seconds 60` | 5+ attempts to SMB/RDP in 60 seconds |
| `classtype:network-scan` | Network scan classification |
| `[445,3389]` | Port group — matches either port in one rule |

**Why targeting these specific ports matters:**
Normal internal traffic rarely involves repeated SYN packets to 445 and 3389 across multiple hosts. Any internal machine doing this is either compromised or being used for unauthorized scanning — both require immediate investigation.

---

## Incident Response Steps

### 1. Triage
- Identify source of internal SMB/RDP scanning: `192.168.0.161`
- Determine if source is a managed internal host or rogue device
- Check how many hosts were scanned — scope of reconnaissance
- Verify if any SMB/RDP connections succeeded after scanning

```bash
# Check Zeek conn.log for successful connections to 445/3389
sudo grep -h "" /opt/zeek/logs/current/conn.log | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        r = json.loads(line)
        if r.get('id.resp_p') in [445, 3389] and r.get('conn_state') == 'SF':
            print(r)
    except: pass
"
```

### 2. Containment
- Block scanning source immediately
```bash
sudo ufw deny from 192.168.0.161
```
- If source is internal machine — isolate from network immediately
- Block SMB/RDP between network segments via firewall rules

### 3. Investigation
- Check if source machine is compromised — review process list, network connections
- Look for credential dumping tools on source machine
- Review authentication logs on all scanned hosts for login attempts
- Check for successful lateral movement — new sessions on scanned hosts

### 4. Remediation
- Segment network — prevent workstations from scanning servers
- Disable SMB v1 — vulnerable to EternalBlue
- Restrict RDP access — allow only from jump server
- Implement network access control (NAC)
- Deploy honeypot on port 445/3389 — any internal connection = immediate alert

---

## Screenshots

- `screenshots/p2-07-rule-200007-lateral-movement.png` — Nmap SMB/RDP scan + Suricata alert
- `screenshots/p2-08-wazuh-dashboard-all-alerts.png` — Wazuh dashboard showing alert

---

## References
- [MITRE ATT&CK T1021](https://attack.mitre.org/techniques/T1021/)
- [EternalBlue MS17-010](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144)
- [Lateral Movement Detection — SANS](https://www.sans.org/reading-room/whitepapers/detection/)
