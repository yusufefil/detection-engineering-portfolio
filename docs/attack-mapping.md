# MITRE ATT&CK Coverage Map

Living document tracking which ATT&CK techniques are covered by detection content in this repo. The goal is **breadth with depth**: every technique listed has at least one tested rule with a documented FP profile, not just a placeholder.

Last updated: 2026-05

## Coverage by tactic

| Tactic | ID | Sigma | QRadar | KQL | Notes |
|---|---|---|---|---|---|
| Initial Access | TA0001 | — | 1 | — | FortiGate SSL VPN brute-force / credential stuffing |
| Execution | TA0002 | — | — | — | *planned* |
| Persistence | TA0003 | — | — | — | *planned* |
| Privilege Escalation | TA0004 | — | — | — | *planned* |
| Defense Evasion | TA0005 | — | — | — | *planned* |
| Credential Access | TA0006 | 1 | — | — | LSASS memory access (T1003.001) |
| Discovery | TA0007 | — | — | — | *planned* |
| Lateral Movement | TA0008 | — | — | — | *planned* |
| Collection | TA0009 | — | — | — | *planned* |
| Command & Control | TA0011 | — | — | — | *planned* |
| Exfiltration | TA0010 | — | — | — | *planned* |
| Impact | TA0040 | — | — | — | *planned* |

## Technique-level detail

### TA0001 — Initial Access

| Technique | Sub-technique | Detection | Status |
|---|---|---|---|
| T1110 — Brute Force | T1110.003 (password spraying), T1110.004 (credential stuffing) | [`qradar/aql-queries/fortigate-vpn-bruteforce.md`](../qradar/aql-queries/fortigate-vpn-bruteforce.md) | stable |

### TA0006 — Credential Access

| Technique | Sub-technique | Detection | Status |
|---|---|---|---|
| T1003 — OS Credential Dumping | T1003.001 (LSASS Memory) | [`sigma/credential-access/mimikatz-lsass-access.yml`](../sigma/credential-access/mimikatz-lsass-access.yml) | test |

## Gaps I'm prioritizing

In order of how often these show up in real triage work, not in theoretical importance:

1. **T1059.001 — PowerShell** (Execution) — encoded command, AMSI bypass patterns
2. **T1078.004 — Cloud Accounts** (Initial Access / Persistence) — impossible-travel and unusual sign-in patterns for M365 / Entra
3. **T1486 — Data Encrypted for Impact** (ransomware behavior signatures: mass file modification, shadow copy deletion)
4. **T1218 — System Binary Proxy Execution** (LOLBAS family — rundll32, regsvr32, mshta)
5. **T1114.003 — Email Forwarding Rule** (M365 mailbox rule abuse)

If you have a technique you'd like to see covered, open an issue.
