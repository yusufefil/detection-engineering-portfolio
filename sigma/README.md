# Sigma Rules

Sigma rules organized by [MITRE ATT&CK](https://attack.mitre.org/) tactic. Each rule follows the [Sigma specification](https://github.com/SigmaHQ/sigma-specification) and is intended to be vendor-neutral — convertible to Splunk SPL, QRadar AQL, Sentinel KQL, Elastic, and others via `sigma-cli` or the bundled [`tools/sigma-to-splunk`](../tools/sigma-to-splunk) pipeline.

## Conventions

- **One rule per file.** File name = lowercase, hyphenated description (`mimikatz-lsass-access.yml`).
- **Status field is honest.** `experimental` = written, not lab-tested. `test` = lab-validated, not production-tuned. `stable` = production-tuned with documented FP profile.
- **Every rule has an ATT&CK tag** in `tags:` (e.g., `attack.credential_access`, `attack.t1003.001`).
- **Falsepositives section is mandatory.** A rule without a known FP scenario is a rule that hasn't been tested enough.

## Tactic folders

| Folder | ATT&CK Tactic | Rules |
|---|---|---|
| [`credential-access/`](./credential-access) | TA0006 | 1 |
| [`execution/`](./execution) | TA0002 | 0 *(planned)* |
| [`defense-evasion/`](./defense-evasion) | TA0005 | 0 *(planned)* |
| [`lateral-movement/`](./lateral-movement) | TA0008 | 0 *(planned)* |

## Testing

Rules in `status: test` or `status: stable` have been validated against telemetry from a lab consisting of:

- Windows 10 22H2, domain-joined
- Sysmon v15 with SwiftOnSecurity baseline config
- Splunk Universal Forwarder → Splunk Enterprise (free license)

Lab build notes live in [`../writeups/lab-setup.md`](../writeups/lab-setup.md) *(planned)*.
