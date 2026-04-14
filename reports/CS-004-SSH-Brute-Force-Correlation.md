# CS-004 — SSH Brute Force: Network vs Host Layer Correlation

## Executive Summary
On April 13, 2026, an SSH brute force attack was detected originating from `192.168.0.161` (Kali Linux) targeting `192.168.0.133` (Ubuntu victim). This case study demonstrates a key SOC analyst skill — correlating the **same attack detected at two independent layers simultaneously**: Suricata IDS at the network layer (rule 200003) and Wazuh HIDS at the host layer (rule 100001 from Project 1). Both alerts mapped to MITRE ATT&CK T1110.001.

---

## Why This Case Study Matters
Most entry-level SOC analysts rely on a single detection source. A mature SOC correlates alerts across multiple layers — network, host, and application — to build a complete picture of an attack. This case study demonstrates exactly that:

| Layer | Tool | Rule | Evidence |
|-------|------|------|----------|
| Network | Suricata IDS | 200003 | TCP SYN floods to port 22 detected |
| Host | Wazuh HIDS | 100001 | SSH authentication failures in /var/log/auth.log |

Same attack. Two independent detection systems. Both fire. That's defense in depth.

---

## Attack Description
SSH brute force attacks systematically try username/password combinations against SSH port 22 until one succeeds. Tools like Hydra can attempt hundreds of combinations per minute.

**Why SSH is targeted:**
- SSH provides full shell access — highest value target
- Many servers expose SSH publicly on port 22
- Weak or default passwords are common
- No lockout by default on many Linux systems

**Attack stages:**
1. Attacker identifies open SSH port via port scan
2. Hydra launches credential stuffing attack
3. If successful — attacker gains shell access
4. Post-compromise — privilege escalation, persistence, lateral movement

---

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Technique | T1110 — Brute Force |
| Sub-technique | T1110.001 — Password Guessing |
| Platform | Linux |
| Data Source | Network Traffic, Authentication Logs |

---

## Attack Simulation

**Attacker machine:** Kali Linux — 192.168.0.161
**Target:** Ubuntu SSH — 192.168.0.133:22

```bash
# Launch SSH brute force with Hydra
hydra -l root -P /usr/share/wordlists/rockyou.txt \
  ssh://192.168.0.133 -t 4
```

Hydra attempts multiple SSH connections per second — triggering both network-layer and host-layer detection simultaneously.

---

## Detection Evidence

### Layer 1 — Suricata network detection
04/13/2026-11:34:32.094908  [] [1:200003:1] CUSTOM SSH Brute Force Detected []
[Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP}
192.168.0.161:39270 -> 192.168.0.133:22

**What Suricata sees:** 5+ TCP SYN packets to port 22 within 60 seconds from same source IP. Pure network-layer visibility — no knowledge of what's inside the SSH session.

### Layer 2 — Wazuh host detection
Wazuh agent on Ubuntu monitors `/var/log/auth.log` in real time. Every failed SSH authentication generates a log entry. Wazuh rule 100001 fires after 4+ failures in 60 seconds from the same IP.

```bash
# Evidence in auth.log
sudo grep "Failed password" /var/log/auth.log | grep "192.168.0.161" | tail -5
```

**What Wazuh sees:** Actual authentication failures with username attempted, source IP, and timestamp — application-layer visibility inside the SSH session.

### Correlation — why both matter
| Attribute | Suricata | Wazuh HIDS |
|-----------|----------|------------|
| Detection point | Network wire | Host auth log |
| What it sees | TCP SYN floods | Failed logins |
| Source IP visible | Yes | Yes |
| Username visible | No | Yes |
| Can be bypassed by | Encryption | Log tampering |
| Complements by | Catching network patterns | Catching auth failures |

Together they provide complete visibility. An attacker who encrypts traffic evades Suricata but not Wazuh. An attacker who clears logs evades Wazuh but not Suricata's network capture.

### Wazuh SIEM alert
- Rule ID: 86601 (Suricata) + 100001 (Wazuh HIDS)
- Both alerts visible in Wazuh dashboard for agent ubuntu-lab-01
- Correlation: same source IP, same timeframe, different detection mechanisms

---

## Custom Rule Breakdown

### Rule 200003 — SSH Brute Force (Suricata)
alert tcp any any -> $HOME_NET 22 (
msg:"CUSTOM SSH Brute Force Detected";
flags:S;
threshold: type both, track by_src, count 5, seconds 60;
classtype:attempted-admin;
sid:200003;
rev:1;
metadata:mitre_technique T1110.001;
)

| Field | Explanation |
|-------|-------------|
| `-> $HOME_NET 22` | Traffic destined for SSH port on any home network host |
| `flags:S` | SYN packets only — connection attempts |
| `threshold: count 5, seconds 60` | 5+ SSH connection attempts in 60 seconds |
| `classtype:attempted-admin` | Attempted admin access classification |

---

## Incident Response Steps

### 1. Triage
- Confirm both Suricata and Wazuh alerts fired for same source IP
- Check if any login succeeded — look for successful auth after brute force
```bash
sudo grep "Accepted password" /var/log/auth.log | grep "192.168.0.161"
```
- Determine attack duration and number of attempts
- Check targeted usernames — root attempts indicate automated attack

### 2. Containment
- Block attacker IP immediately at firewall
```bash
sudo ufw deny from 192.168.0.161
```
- If login succeeded — isolate host immediately, assume compromise

### 3. Investigation
- Review full auth.log for successful logins post-brute-force
- Check for new user accounts created
- Review bash history for post-compromise commands
- Check for new cron jobs or systemd services (persistence)

### 4. Remediation
- Disable password authentication — use SSH keys only
```bash
# In /etc/ssh/sshd_config
PasswordAuthentication no
```
- Move SSH to non-standard port
- Implement fail2ban for automatic IP blocking
- Restrict SSH access by IP via UFW

---

## Screenshots

- `screenshots/p2-03-rule-200003-ssh-bruteforce.png` — Hydra attack + Suricata alert
- `screenshots/p2-08-wazuh-dashboard-all-alerts.png` — Wazuh dashboard correlation view

---

## References
- [MITRE ATT&CK T1110.001](https://attack.mitre.org/techniques/T1110/001/)
- [Hydra Documentation](https://github.com/vanhauser-thc/thc-hydra)
- [SSH Hardening Guide](https://www.ssh.com/academy/ssh/security)
