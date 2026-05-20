# Methodology

How I write, test, and ship detection content. Short, pragmatic, and the same process I follow whether the target SIEM is QRadar, Sentinel, Splunk, or Elastic.

## The five-step loop

### 1. Pick a technique, not an alert

Every rule starts with a MITRE ATT&CK technique or sub-technique — not "we saw something weird in the logs." The procedure examples on the ATT&CK page are the spec. If a technique has no documented procedures, it's a hint that the detection may be too speculative.

### 2. Map the telemetry

Before writing a query, list the data sources that would surface the technique. ATT&CK helpfully publishes a [data source mapping](https://attack.mitre.org/datasources/) per technique. If the customer / lab environment doesn't produce that telemetry, the detection won't fire — that's a visibility gap to flag, not a rule to ship.

### 3. Build against real telemetry

Either:
- A lab (Windows 10 + Sysmon with SwiftOnSecurity config + Splunk free / Sentinel free tier), or
- Sanitized production samples (see [Sanitization checklist](#sanitization-checklist) below)

Synthetic data is fine for syntax-checking; it's not enough to claim a rule works.

### 4. Document the false-positive profile

Every rule ships with at least one known FP scenario in its `falsepositives` block. A rule with no documented FPs hasn't been tested against enough variety. In QRadar specifically, the FP profile drives the tuning approach: reference set whitelist, threshold adjustment, building-block prerequisites, or — if FPs dominate — a rewrite.

### 5. Tag for ATT&CK, version it, ship it

Tag with technique ID + sub-technique. Commit with a status (`experimental` / `test` / `stable`). For QRadar, store the CRE export and the building-block dependency list. For Sigma, the YAML is canonical and the SIEM-specific translation is generated, not maintained.

---

## Sanitization checklist

Run through this list **before every commit** that touches detection content derived from a customer environment.

### Network identifiers

- [ ] No real public IP addresses → replace with [RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
- [ ] No internal IPs that map to a real customer → use [RFC 1918](https://datatracker.ietf.org/doc/html/rfc1918) (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) generically
- [ ] No real domain names → use `example.com`, `example.org`, `example.net` ([RFC 2606](https://datatracker.ietf.org/doc/html/rfc2606))
- [ ] No real hostnames or asset tags

### Customer / tenant identifiers

- [ ] No customer name (full, abbreviated, or codename) anywhere — README, rule, AQL, comment
- [ ] No tenant ID, domain context, or QRadar domain name
- [ ] No reference set name that includes a customer identifier (rename to generic, e.g., `External_AllowList_VPN`)
- [ ] No building-block name that names a customer
- [ ] No internal ticket IDs or case numbers

### Personal / account data

- [ ] No real usernames (replace with `user01`, `admin01`, `svc_backup`)
- [ ] No real email addresses (use `[email protected]`)
- [ ] No employee names in comments or commit messages

### Vendor / device specifics

- [ ] No device serial numbers, MAC addresses, or hardware identifiers
- [ ] No vendor license keys, agent IDs, or activation codes

### Sanity check

- [ ] Re-read the diff with fresh eyes (or wait an hour)
- [ ] Search the diff for the customer name one more time
- [ ] If you're not sure, don't commit. Open an issue and ask.

---

## What I don't put in this repo

To pre-empt the obvious question:

- **Production CRE rule exports.** They contain too much tenant-specific configuration to safely sanitize. The logic is described as recipes (`qradar/cre-rules/*.md`) instead.
- **Customer incident reports.** These belong in customer ticketing systems, not on GitHub.
- **Anything I'm not 100% authorized to publish.** When in doubt, don't.

---

## Acknowledgments

This methodology draws on the [SigmaHQ contribution guidelines](https://github.com/SigmaHQ/sigma/wiki/Contributing-Guidelines), the [Splunk Security Content](https://github.com/splunk/security_content) repository conventions, and the [Detection Engineering Maturity Matrix](https://detectionengineering.io/) framing. Standing on shoulders.
