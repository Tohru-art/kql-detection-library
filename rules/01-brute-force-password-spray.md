# Rule 01 — Brute Force / Password Spray Detection

## What it detects
An account receiving 10+ failed sign-ins within a 10-minute window. Flags accounts hit from multiple IPs as a spray indicator.

## MITRE ATT&CK
- Tactic: Credential Access (TA0006)
- Technique: Brute Force — Password Spraying (T1110.003)

## Sentinel Table
`SigninLogs`

## KQL Query
```kql
// Table: SigninLogs (Azure AD / Entra ID sign-in events)
SigninLogs
// Only failed sign-ins (ResultType 0 = success)
| where ResultType != "0"
// Exclude known service accounts to cut noise
| where UserPrincipalName !endswith "svc@yourdomain.com"
// Bucket events into 10-minute windows per user
| summarize
    FailedAttempts = count(),
    DistinctIPs    = dcount(IPAddress),
    FirstSeen      = min(TimeGenerated),
    LastSeen       = max(TimeGenerated)
    by UserPrincipalName, bin(TimeGenerated, 10m)
// Threshold: 10+ failures in the window
| where FailedAttempts >= 10
// Flag spray pattern: same account hit from 3+ IPs
| extend IsSpray = DistinctIPs > 3
| project TimeGenerated, UserPrincipalName,
          FailedAttempts, DistinctIPs, IsSpray,
          FirstSeen, LastSeen
| order by FailedAttempts desc
```

## Tuning Tips
- Raise threshold to 20+ in high-traffic environments
- Add `| where IPAddress !in (trusted_ip_list)` to exclude VPN egress IPs
- ResultType 50126 = invalid credentials, 50053 = account locked
- Pair with a successful login follow-up query to catch post-spray compromise

## Recommended Severity
- **High** — if `IsSpray == true` or `FailedAttempts > 50`
- **Medium** — otherwise


## Threat Investigation — Live Environment

## Real World Finding

During hands-on testing in the Log(N) Pacific cyber range (April 1, 2026),
rule 01 surfaced account `cdeb4c73...@lognpacific.com` with 23 failed
attempts across 3 IPs over a 45-minute window.

Drill-down investigation revealed a multi-stage attack:
- ResultType 50126 — wrong password attempts from iPhone (IP: 50.47.229.209)
- ResultType 50074 — password correct but MFA blocking (IP: 173.239.254.251)
- ResultType 500121 — repeated MFA push failures across iPhone + Mac
- ResultType 50133 — session invalidated due to recent password change
- Third IP (85.8.130.26) introduced mid-attack

Assessment: MFA fatigue attack pattern. Attacker had correct credentials
but could not bypass MFA. Three source IPs suggest coordinated attempt
across multiple devices or proxies.

Escalation: Would escalate to Tier 2 for account lockout and credential
reset. Password change (50133) suggests account may have been previously
compromised.
