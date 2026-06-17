# Investigation Writeups

End-to-end walkthroughs of attack chains: what the attacker did, what telemetry it produced, how a detection would catch it, and what a SOC analyst's response workflow looks like.

These are *educational* writeups built on lab telemetry, not customer incident reports.

## Planned writeups

- [ ] **Mimikatz attack chain** — initial access → privilege escalation → LSASS dump → credential reuse. Covers Sysmon Event IDs 1, 7, 10, 11 and three Sigma rules. Lab: Windows 10 + Sysmon + Splunk.
- [ ] **Lateral movement via SMB / PsExec** — service creation, named-pipe communication, remote process execution. Covers Windows Event IDs 4624 (Type 3), 4697, 5145.
- [ ] **FortiGate SSL VPN brute-force investigation** — companion narrative to [`../qradar/aql-queries/fortigate-vpn-bruteforce.md`](../qradar/aql-queries/fortigate-vpn-bruteforce.md). Walks through the AQL hunt, what was found, how the source was blocklisted, and what the follow-up CRE rule looks like.

Each writeup follows the same structure:

1. **Threat model** — the attacker's goal and approach
2. **Telemetry** — what the attack produces in logs, with annotated samples
3. **Detection** — link to the Sigma / AQL / KQL content that catches it
4. **Response** — the analyst's triage workflow, escalation criteria, and containment steps
5. **References** — ATT&CK, vendor advisories, related research
