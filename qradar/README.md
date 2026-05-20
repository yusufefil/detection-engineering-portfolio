# QRadar Detection Content

This folder contains QRadar AQL queries, CRE (Custom Rule Engine) rule patterns, and Custom Event Property (CEP) examples produced during my day-to-day SOC L2 / detection-engineering work.

**Sanitization note:** Nothing here is copied from a production tenant. Customer names, asset IDs, real IP addresses, and tenant-specific reference set names have been replaced with RFC 1918 / RFC 5737 ranges and generic identifiers. The detection *logic* and *AQL syntax* is real; the *context* is reconstructed.

## Contents

| Folder | What's in it |
|---|---|
| [`aql-queries/`](./aql-queries) | Standalone AQL queries for hunting, validation, and ad-hoc investigation |
| [`cre-rules/`](./cre-rules) | CRE rule logic — described as pseudo-rule + condition list (QRadar rules don't export cleanly as text, so these are written as recipes) |
| [`custom-event-properties/`](./custom-event-properties) | CEP regex examples for parsing fields out of unparsed payloads |

## QRadar version notes

Content is written against QRadar 7.5.x AQL syntax. Older versions may not support every function used (e.g., `INCIDR()`, `STRPOS()` parameter handling).

## Why no full CRE exports?

QRadar's CRE rules don't serialize to a human-readable, portable format. Posting raw rule XML would also risk leaking tenant-specific configuration. Instead, each `cre-rules/` entry is documented as:

- **Triggering log source(s)** — generic descriptions, not customer device names
- **Building blocks used** — referenced by purpose, not by tenant ID
- **Test conditions** — the actual rule logic in plain English
- **Response action** — offense category, severity, magnitude
- **Tuning notes** — known FP patterns and reference-set patterns
