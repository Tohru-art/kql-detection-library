# KQL Detection Library

A collection of production-ready KQL detection rules for Microsoft Sentinel and Microsoft Defender for Endpoint.

Each rule includes a KQL query with inline comments, MITRE ATT&CK mapping, tuning tips, and recommended alert severity.

## Rules

| # | Rule | MITRE Technique | Severity |
|---|------|----------------|----------|
| 01 | [Brute Force / Password Spray](rules/01-brute-force-password-spray.md) | T1110.003 | High |

## Structure
```
rules/
└── 01-brute-force-password-spray.md
```

## Tools
Microsoft Sentinel · Microsoft Defender for Endpoint · KQL (Kusto Query Language)
