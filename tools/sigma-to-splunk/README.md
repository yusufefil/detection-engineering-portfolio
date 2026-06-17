# sigma-to-splunk

A small Python utility that takes Sigma rule YAML files and emits Splunk SPL queries, with optional inline ATT&CK annotation and saved-search XML wrapper output.

## Background

Built originally as part of a take-home exercise involving a Mimikatz-based attack chain — three Sigma rules needed to ship into a Windows 10 / Sysmon / Splunk lab. Rather than hand-translate, I wrote this pipeline so the same Sigma source files could land in multiple target SIEMs.

The official [`sigma-cli`](https://github.com/SigmaHQ/sigma-cli) and `pySigma` libraries are the canonical solution and what you should reach for in production — this is a lightweight learning project that helped me understand the backend-translation logic from the inside.

## Status

Pre-release / lab-grade. Not a replacement for `sigma-cli`. Posted here as evidence of working with Sigma at the pipeline level, not as a tool to depend on.

## Planned content

- [ ] `sigma_to_splunk.py` — single-file translator with basic field-mapping logic
- [ ] Sample rules in `examples/` covering the three core attack-chain detections (LSASS access, mimikatz module load, suspicious child of lsass.exe)
- [ ] Test fixtures and expected-output snapshots

## See also

- [`SigmaHQ/sigma`](https://github.com/SigmaHQ/sigma) — main Sigma rule repository
- [`SigmaHQ/pySigma`](https://github.com/SigmaHQ/pySigma) — the canonical Python library for Sigma processing
