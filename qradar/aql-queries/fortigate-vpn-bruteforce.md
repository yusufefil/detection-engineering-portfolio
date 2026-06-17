# FortiGate SSL VPN Pre-Authentication Failure Hunt

**ATT&CK:** [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) / [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
**Log source:** FortiGate (FortiOS event log; DSM auto-mapped)
**Status:** stable
**Author:** Yusuf Efil

## Scenario

External clients hitting the SSL VPN portal with pre-authentication failures — i.e., the connection negotiates but never reaches a successful auth state. This is the signature of credential stuffing, password spraying, or unauthenticated scanning behavior against the VPN endpoint.

A real case that prompted this query: a sustained burst of pre-auth failures from a single `/24` hosted on a Netherlands-based VPS provider, targeting the SSL VPN portal of a customer environment over a multi-hour window. Volume was just below the per-source rate threshold that would have triggered the vendor's stock rule, which is why a custom AQL hunt was needed.

## Query

```sql
SELECT
    sourceip                                                   AS "Source IP",
    COUNT(*)                                                   AS "Failure Count",
    UNIQUECOUNT(username)                                      AS "Unique Usernames Tried",
    MIN(DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss'))          AS "First Seen",
    MAX(DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss'))          AS "Last Seen"
FROM events
WHERE
    LOGSOURCETYPENAME(devicetype) = 'FortiGate Security Gateway'
    AND   "Event Category" = 'vpn'
    AND   LOWER(payload) LIKE '%ssl%vpn%'
    AND   (LOWER(payload) LIKE '%fail%' OR LOWER(payload) LIKE '%denied%')
    AND   NOT INCIDR('10.0.0.0/8',     sourceip)
    AND   NOT INCIDR('172.16.0.0/12',  sourceip)
    AND   NOT INCIDR('192.0.2.0/24',   sourceip)
GROUP BY sourceip
HAVING COUNT(*) >= 10
ORDER BY "Failure Count" DESC
LAST 24 HOURS
```

## How it works

| Clause | Purpose |
|---|---|
| `LOGSOURCETYPENAME(devicetype) = 'FortiGate Security Gateway'` | Scopes to FortiGate events only — faster than filtering on log source name |
| `"Event Category" = 'vpn'` | Uses QRadar's parsed event category; falls back to payload match if CEP not present |
| `LIKE '%ssl%vpn%' AND LIKE '%fail%/%denied%'` | Pre-auth failure signature in FortiOS event payloads |
| `NOT INCIDR('10.0.0.0/8', sourceip)` | Excludes internal RFC 1918 ranges so we focus on external sources |
| `HAVING COUNT(*) >= 10` | Suppresses noise from single-attempt typos / legitimate misconfigured clients |
| `UNIQUECOUNT(username)` | High value with high failure count = credential stuffing; low value with high count = password spraying / single-user brute force |

## Interpretation

| Pattern | Likely meaning |
|---|---|
| 1 source, 1 username, 100+ failures | Brute force against a known user |
| 1 source, many usernames, few attempts each | Credential stuffing — list of leaked creds being tried |
| Many sources, same username | Distributed password spray (less common against VPN; common against M365) |
| 1 source, no username field populated | Unauthenticated scanning — bot probing the portal |

## Tuning notes

- The `payload LIKE '%fail%'` match catches multiple FortiOS message types. If your DSM is recent enough to parse the `action` field cleanly, prefer `"Event Action" IN ('login_failed', 'ssl_login_fail')` for accuracy and performance.
- For multi-tenant environments, add a `domain` or `customer` reference set filter to scope the hunt.
- This query runs in the AQL search interface. To productize as a CRE rule, see `cre-rules/fortigate-vpn-bruteforce-cre.md`.

## Related

- ATT&CK [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- ATT&CK [T1110.004 — Credential Stuffing](https://attack.mitre.org/techniques/T1110/004/)
- Fortinet PSIRT advisories on SSL VPN pre-auth vulnerabilities (relevant CVEs to keep current with)
