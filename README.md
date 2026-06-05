# Account-Level Behavioural Baselining – Privilege Escalation Activity (Microsoft Sentinel)

## Objective

This lab develops an account-level behavioural baseline for privilege escalation activity using Syslog telemetry within Microsoft Sentinel.

The goal is to understand which user accounts perform privilege escalation and establish a foundation for future behavioural detections.

---

## Background

Previous labs focused on:

- multi-stage detections
- behavioural detection evaluation
- timing-based correlation
- stealth attacker scenarios

This exercise introduces account-level behavioural analysis.

---

## Telemetry Validation

### Latest Syslog Event

```kql
Syslog
| summarize LatestLog = max(TimeGenerated)
```

Result:

```text
2026-06-05T05:49:33.003738Z
```

---

### Log Volume Check

```kql
Syslog
| where TimeGenerated > ago(24h)
| count
```

Result:

```text
1544
```

---

## Telemetry Investigation

Observed Syslog format:

```text
pam_unix(sudo:session): session opened for user root(uid=0) by azureuser(uid=1000)
```

This provided the account information required for behavioural baselining.

---

## Account Extraction Query

```kql
Syslog
| where TimeGenerated > ago(30d)
| where SyslogMessage has "sudo:session"
| extend Account = extract(@"by (\w+)\(uid=", 1, SyslogMessage)
| where isnotempty(Account)
| summarize PrivilegeEscalations = count() by Account
| order by PrivilegeEscalations desc
```

---

## Results

| Account | PrivilegeEscalations |
|----------|----------|
| azureuser | 1 |

---

## Key Insight

> Behavioural detections become more effective when they are based on deviations from normal user behaviour rather than isolated security events.

---

## Future Work

Future development will explore:

- rare privilege escalation detection
- first-time privilege escalation activity
- behavioural deviation analysis
- account risk profiling
