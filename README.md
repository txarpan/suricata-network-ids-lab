# Network IDS & Traffic Analysis Lab — Suricata + Zeek + Wazuh

A hands-on Network Intrusion Detection and Traffic Analysis lab built to detect real-world network-layer attacks using custom Suricata rules, Zeek protocol logs, and Wazuh SIEM — all mapped to the MITRE ATT&CK framework.

> **Extends:** [Detection Engineering & SOC Lab — Wazuh SIEM](https://github.com/txarpan/wazuh-soc-detection-lab)
> Project 1 covers host-based detection. This project adds network-layer detection — together they form a complete SOC analyst defensive stack.

---

## Lab Architecture

| Component | Details |
|-----------|---------|
| SIEM | Wazuh 4.14.3 (Dockerized, single-node) |
| IDS | Suricata 8.0.4 (af-packet mode, IDS) |
| NSM | Zeek 8.1.1 (JSON logging) |
| Attacker | Kali Linux — 192.168.0.161 |
| Victim (Linux) | Ubuntu 24.04.4 LTS — 192.168.0.133 |
| Host | Fedora Linux — 192.168.0.224 |
| Tools | Nmap, Hydra, hping3, Python, iodine |

---

## What This Lab Demonstrates

- Deploying Suricata IDS in af-packet mode on a live network
- Writing custom Suricata rules from scratch mapped to MITRE ATT&CK
- Capturing and analyzing network protocol logs with Zeek
- Integrating Suricata EVE JSON and Zeek logs into Wazuh SIEM
- Detecting network-layer attacks: port scans, DNS tunneling, C2 beaconing, lateral movement
- Correlating network-layer (Suricata/Zeek) and host-layer (Wazuh) alerts for the same attack
- False positive tuning and threshold-based detection
- SOAR automation for automated attacker IP blocking

---

## Attack Scenarios

| # | Attack | MITRE Technique | Detection | Severity |
|---|--------|----------------|-----------|----------|
| 1 | TCP SYN Port Scan | T1046 — Network Service Discovery | Custom Rule 200001 | Medium |
| 2 | UDP Port Scan | T1046 — Network Service Discovery | Custom Rule 200002 | Medium |
| 3 | SSH Brute Force (network layer) | T1110.001 — Password Guessing | Custom Rule 200003 | High |
| 4 | DNS Tunneling | T1071.004 — DNS C2 | Custom Rule 200004 | Critical |
| 5 | C2 HTTP Beaconing | T1071.001 — HTTP C2 | Custom Rule 200005 | Critical |
| 6 | ICMP Flood Recon | T1595 — Active Scanning | Custom Rule 200006 | Medium |
| 7 | Lateral Movement Scan | T1021 — Remote Services | Custom Rule 200007 | High |

---

## Custom Suricata Rules

Located in `/rules/custom.rules`

| Rule ID | Description | Trigger | MITRE |
|---------|-------------|---------|-------|
| 200000 | ICMP Ping Detection (test rule) | Any ICMP type 8 | T1595 |
| 200001 | TCP SYN Port Scan | 20+ SYN packets in 10s | T1046 |
| 200002 | UDP Port Scan | 20+ UDP packets in 10s | T1046 |
| 200003 | SSH Brute Force | 5+ SSH connections in 60s | T1110.001 |
| 200004 | DNS Tunneling | 50+ DNS queries in 10s | T1071.004 |
| 200005 | C2 HTTP Beaconing | Repeated /beacon URI hits | T1071.001 |
| 200006 | ICMP Flood | 100+ ICMP in 5s | T1595 |
| 200007 | Lateral Movement Scan | SMB/RDP port scanning | T1021 |

---

## Case Studies

| ID | Title | Status |
|----|-------|--------|
| CS-001 | TCP/UDP Port Scan Detection | 🔄 In Progress |
| CS-002 | DNS Tunneling Detection & Analysis | 🔄 In Progress |
| CS-003 | C2 HTTP Beaconing Detection | 🔄 In Progress |
| CS-004 | SSH Brute Force — Network vs Host Correlation | 🔄 In Progress |
| CS-005 | Lateral Movement Detection | 🔄 In Progress |

---

## Repository Structure

suricata-network-ids-lab/
├── README.md
├── rules/
│   └── custom.rules                    # 12 custom Suricata rules, MITRE mapped
├── zeek/
│   ├── local.zeek                      # custom Zeek scripts
│   └── zeek-queries.md                 # threat hunting queries
├── wazuh-integration/
│   ├── ossec.conf.snippet              # Suricata + Zeek Wazuh agent config
│   └── suricata.yaml.backup            # configured Suricata main config
├── attack-simulation/
│   ├── c2-beacon.py                    # C2 beaconing simulation script
│   └── dns-tunnel-sim.sh               # DNS tunneling test script
├── soar/
│   └── auto-block-v2.py               # Suricata alert → UFW auto-block
├── reports/
│   ├── CS-001-Port-Scan.md
│   ├── CS-002-DNS-Tunneling.md
│   ├── CS-003-C2-Beaconing.md
│   ├── CS-004-SSH-Correlation.md
│   ├── CS-005-Lateral-Movement.md
│   └── FP-Tuning-Report.md
├── logs/                               # sanitized sample EVE JSON, Zeek logs
└── screenshots/                        # evidence and verification proof

---

## Tools & Technologies

`Suricata 8.0.4` `Zeek 8.1.1` `Wazuh 4.14.3` `Docker` `Kali Linux` `Ubuntu 24.04`
`Nmap` `Hydra` `hping3` `Python` `MITRE ATT&CK` `Bash` `UFW` `SSH`

---

## Author

**Arpan Mukherjee**
Cybersecurity Engineer | Detection Engineering | SOC Analyst | RHCSA Certified
[GitHub](https://github.com/txarpan)
