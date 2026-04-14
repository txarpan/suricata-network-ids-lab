# False Positive Tuning Report

## Overview
During lab testing, several false positive alerts were identified and
resolved. This report documents each FP encountered, root cause
analysis, and the tuning decision made.

---

## FP-001 — UDP Port Scan false positives from DNS traffic

**Rule:** 200002 — CUSTOM UDP Port Scan Detected
**Symptom:** Rule fired repeatedly on normal DNS traffic between
`192.168.0.224` (Fedora host) and `192.168.0.1` (router) on port 53.

**Root cause:** DNS queries generate high-volume UDP traffic naturally.
The threshold of 20 UDP packets in 10 seconds was too low for a busy
network — legitimate DNS resolution triggered the rule.

**Evidence:**
04/13/2026-12:14:24  [1:200002:1] CUSTOM UDP Port Scan Detected
{UDP} 192.168.0.1:53 -> 192.168.0.224:40557

**Tuning decision:** The rule threshold was kept at 20/10s for lab
demonstration purposes. In a production environment, DNS traffic should
be excluded using a suppress rule:

**Status:** Documented — acceptable for lab environment

---

## FP-002 — ICMP Ping rule firing on legitimate traffic

**Rule:** 200000 — CUSTOM ICMP Ping Detected
**Symptom:** Rule fired on legitimate ping traffic between lab machines
during normal connectivity testing — not only during attack simulation.

**Root cause:** Rule 200000 uses `any any` as source — intentionally
broad for the test rule. Any ICMP type 8 packet triggers it regardless
of source.

**Tuning decision:** Rule 200000 is a test rule only — not intended for
production use. Production ICMP detection should use rule 200006 which
requires 100+ packets in 5 seconds, eliminating single-ping false
positives.

**Status:** Acceptable — test rule behavior as designed

---

## FP-003 — ET INFO Python SimpleHTTP ServerBanner alerts

**Rule:** ET INFO ruleset (Emerging Threats)
**Symptom:** Multiple ET INFO alerts fired during C2 beaconing
simulation because Python's HTTP server sends a recognizable
`Server: SimpleHTTP` banner — detected by ET INFO signatures.

**Evidence visible in Wazuh dashboard:**
Suricata: Alert - ET INFO Python SimpleHTTP ServerBanner

**Root cause:** ET INFO rules detect known software banners for
inventory purposes. Python's built-in HTTP server is flagged because
it's commonly used in post-exploitation scenarios.

**Tuning decision:** These alerts are actually valuable — they confirm
that Suricata's ET ruleset correctly identified the C2 server software.
No tuning applied — alerts kept as additional evidence layer.

**Status:** True positive behavior — ET ruleset working correctly

---

## FP-004 — SSH Brute Force rule sensitive threshold

**Rule:** 200003 — CUSTOM SSH Brute Force Detected
**Symptom:** Rule could potentially fire on legitimate SSH connection
retries during network instability — 5 connections in 60 seconds is
a low threshold.

**Root cause:** Threshold set aggressively low for lab demonstration.
In production environments with stable networks, 5 SYN packets to
port 22 in 60 seconds from the same source is still suspicious and
warrants investigation.

**Tuning decision:** Threshold kept at 5/60s for lab. Production
environments with high SSH usage (automated deployments, monitoring
agents) should increase to 10-15/60s and whitelist known management
IPs.

**Status:** Documented — threshold appropriate for lab environment

---

## Summary

| FP ID | Rule | Root Cause | Resolution |
|-------|------|------------|------------|
| FP-001 | 200002 UDP Scan | DNS traffic volume | Suppress rule recommended |
| FP-002 | 200000 ICMP Ping | Broad test rule | Test rule by design |
| FP-003 | ET INFO | Python HTTP banner | True positive — kept |
| FP-004 | 200003 SSH BF | Low threshold | Documented for production |

---

## Key Takeaways

- Threshold tuning is critical — too low generates noise, too high
  misses attacks
- Whitelisting known-good IPs (management servers, DNS servers)
  reduces FP rate significantly
- ET INFO alerts should be reviewed separately from ET ATTACK alerts —
  different severity implications
- Every suppression decision should be documented with justification —
  suppressing without documentation creates blind spots
