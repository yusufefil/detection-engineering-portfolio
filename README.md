# Detection Engineering Portfolio

> Public collection of detection content — Sigma rules, QRadar AQL/CRE examples, KQL queries, and investigation writeups — produced as part of my day-to-day work as a SOC L2 Analyst & Detection Engineer in a managed multi-tenant SIEM environment.

All content is **sanitized**: no customer names, no real IP addresses, no production rule logic that would expose tenant-specific configurations. Where examples are derived from real cases, identifying details are replaced with RFC 1918 / RFC 5737 addresses and generic placeholders.

---

## About me

I'm Yusuf Efil — SOC L2 Analyst & Detection Engineer working primarily in IBM QRadar, currently expanding into Microsoft Sentinel / KQL and Sigma-based Detection-as-Code. OSDA-certified (OffSec). Based in Türkiye, open to remote roles.

- LinkedIn — `[linkedin.com/in/yusufefil]`
- Email — `yusufefil@outlook.com`

---

## What's in here

| Folder | What it contains |
|---|---|
| [`sigma/`](./sigma) | Sigma rules organized by MITRE ATT&CK tactic, with test notes and false-positive considerations |
| [`qradar/`](./qradar) | QRadar AQL queries, CRE rule patterns (logic only — no tenant configs), and Custom Event Property examples |
| [`kql/`](./kql) | Microsoft Sentinel KQL queries (in progress — active learning) |
| [`tools/`](./tools) | Detection-engineering tooling — including `sigma_to_splunk` translation pipeline |
| [`writeups/`](./writeups) | End-to-end investigation writeups: attack chain → telemetry → detection → response |
| [`docs/`](./docs) | ATT&CK coverage map, methodology, and sanitization policy |

---

## Coverage at a glance

See [`docs/attack-mapping.md`](./docs/attack-mapping.md) for the full MITRE ATT&CK coverage table. Quick summary:

| Tactic | Sigma | QRadar | KQL |
|---|---|---|---|
| Initial Access | — | 1 | — |
| Execution | 1 | — | — |
| Credential Access | 1 | — | — |

Updated as new content lands. The aim is breadth over speed — a few well-tested rules with documented FP behavior beat dozens of untested ones.

---

## How I write detections

Short version, longer in [`docs/methodology.md`](./docs/methodology.md):

1. **Start from the technique, not the alert.** Pick a MITRE ATT&CK sub-technique, read the procedure examples, then map the telemetry that would surface it.
2. **Write the query against real telemetry.** Either a lab (Windows 10 + Sysmon + Splunk/Sentinel) or sanitized production samples.
3. **Document the false-positive profile.** Every rule ships with at least one known FP scenario and a tuning suggestion.
4. **Map to ATT&CK explicitly.** Technique ID, sub-technique ID, and data sources used.
5. **Version-control everything.** Every rule has a `status` field (`experimental` / `test` / `stable`).

---

## Sanitization policy

Nothing in this repository was copied from a customer environment as-is. Every rule, query, and writeup has been:

- Stripped of tenant identifiers, asset names, and internal hostnames
- Re-anchored on lab telemetry or generic data (RFC 1918 / RFC 5737 / `example.com`)
- Reviewed against the [sanitization checklist](./docs/methodology.md#sanitization-checklist) before commit

If you spot anything that looks identifying, please open an issue — I'll fix it immediately.

---

## License

MIT — see [`LICENSE`](./LICENSE). Use freely, attribution appreciated.
