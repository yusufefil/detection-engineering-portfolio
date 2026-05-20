# Microsoft Sentinel — KQL Queries

> **Status: In progress.** I'm actively building out KQL content as part of my pivot from QRadar-only to a multi-SIEM detection-engineering skillset. Tracking progress against the [SC-200 (Security Operations Analyst)](https://learn.microsoft.com/en-us/credentials/certifications/exams/sc-200/) exam path and Sentinel Applied Skills.

Each KQL query that lands here will follow the same conventions as the rest of this repo:

- MITRE ATT&CK technique mapping in the header
- Table(s) queried and assumed data connectors
- Inline comments on filter logic
- Documented false-positive scenarios

## Roadmap (next 90 days)

- [ ] **Sign-in anomaly** — `SigninLogs` impossible travel patterns (T1078.004 — Cloud Accounts)
- [ ] **Suspicious PowerShell** — `DeviceProcessEvents` with encoded commands (T1059.001)
- [ ] **OAuth consent abuse** — `OfficeActivity` consent grants to unverified apps (T1528)
- [ ] **Mailbox forwarding rule** — `OfficeActivity` New-InboxRule with ForwardTo (T1114.003)
- [ ] **Mimikatz LSASS access** — port of `../sigma/credential-access/mimikatz-lsass-access.yml` to `DeviceEvents` table

## Why this folder is empty (for now)

I'd rather ship one validated KQL query than commit a dozen untested ones. Each query lands here only after I've run it against real Sentinel telemetry in a lab tenant and documented at least one FP scenario.

Watch the [main repo coverage table](../README.md#coverage-at-a-glance) for updates.
