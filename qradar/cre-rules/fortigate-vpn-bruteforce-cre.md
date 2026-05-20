# CRE Rule: FortiGate SSL VPN — External Pre-Auth Failure Volume

**ATT&CK:** T1110 — Brute Force (T1110.003 password spraying / T1110.004 credential stuffing)
**Log source type:** FortiGate Security Gateway
**Status:** stable
**Author:** Yusuf Efil

> This entry documents the CRE *recipe* — the logic, building blocks, and tuning model — not a tenant-specific export. Reproduce in your environment by recreating the building blocks below.

## Purpose

Operationalize the [`fortigate-vpn-bruteforce.md`](../aql-queries/fortigate-vpn-bruteforce.md) hunt as a real-time CRE rule that opens an offense when an external source generates a meaningful volume of SSL VPN pre-authentication failures.

## Building blocks required

| BB | Purpose |
|---|---|
| `BB:HostDefinition: External Source` | Source IP is NOT in any RFC 1918 range and NOT in the tenant's documented external partner allow-list |
| `BB:CategoryDefinition: VPN Authentication Failure` | Matches FortiGate `subtype = vpn` events with `status / action` indicating pre-auth failure |
| `BB:LogSourceType: FortiGate` | Scopes to FortiGate Security Gateway log source type |

## Rule logic (plain English)

> Apply when:
> - Event matches `BB:LogSourceType: FortiGate`
> - AND event matches `BB:CategoryDefinition: VPN Authentication Failure`
> - AND source IP matches `BB:HostDefinition: External Source`
> - AND when at least **10 events** in **5 minutes** with the same source IP

## Response

| Field | Value |
|---|---|
| Severity | 5 |
| Credibility | 7 |
| Relevance | 6 |
| Offense indexing | Source IP |
| Annotation | "External SSL VPN pre-auth failure burst — investigate for credential stuffing / password spraying" |

## Tuning model

**Phase 1 (deploy):** thresholds as above. Expect FPs from:

- Misconfigured legitimate clients in vendor / partner ranges → add to the external partner allow-list referenced by `BB:HostDefinition: External Source`
- Internal QA / pentest activity hitting from external NAT → coordinate with customer to receive scheduled-test windows and add a time-window suppression

**Phase 2 (one week in):** review offense magnitudes. If the rule produces > 5 offenses/day with low triage value, raise the count threshold to 20 in 5 minutes and add a `UNIQUECOUNT(username) >= 3` correlation step to focus on credential stuffing signature specifically.

**Phase 3 (stable):** layer a follow-up rule for *successful* authentication from a source that previously appeared in this offense (cross-correlation via reference set with a 1-hour TTL).

## Known FP patterns

1. **Slow brute-force** under the threshold. Mitigated by a sibling rule with longer time window (1 hour, count 30) at lower severity.
2. **Distributed credential stuffing** from many sources, each below the per-source threshold. Mitigated by a separate rule keyed on `username` rather than `sourceip`.
3. **NAT collapse** — multiple legitimate users behind one corporate NAT triggering the threshold. Resolve by tenant-specific allow-list, not by raising the global threshold.

## Test approach

In a lab, scripted FortiOS-shaped events were generated with [SimuLog](https://github.com/example/simulog) *(or use any QRadar event injector tool)* and replayed against the rule. The rule fired at 10 events in 5 minutes as designed and did not fire below threshold or for internal-range sources.
