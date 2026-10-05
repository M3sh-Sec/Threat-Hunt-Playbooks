# H-00 — How to use these hunts

Each hunt follows the same loop: state a testable hypothesis, confirm the data source is collected, run the baseline query, stack and filter outliers, pivot on suspicious hits, then either escalate or convert the logic into a detection. Run every query first over 30 days to baseline, then narrow to 7 days for daily hunting.

**Hunt loop (apply to every hunt below)**

1. **Validate telemetry** — confirm the listed data source exists and is parsed (run a simple count by host/account for the last 24h).
2. **Baseline** — run the query over 30 days and stack by the key field (process path, DLL hash, user, API caller).
3. **Outlier review** — focus on rare values (count of hosts ≤ 3, first-seen in last 7 days, unsigned, user-writable paths).
4. **Pivot** — for each lead, pull parent/child process tree, network connections, logon session and same-hash prevalence.
5. **Decide** — benign (document + allowlist), suspicious (escalate to IR), or detection-worthy (convert to scheduled rule).
6. **Record** — log hunt ID, date range, queries run, hits, outcome, and tuning changes.

**Query language conventions**

| Platform | Language used here | Primary data assumed |
| --- | --- | --- |
| Splunk | SPL with CIM data models where possible, raw Sysmon/WinEventLog otherwise | Sysmon (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`), Windows Security, Linux auditd, cloud add-ons (AWS, Azure, GCP, Salesforce) |
| CrowdStrike | Falcon Next-Gen SIEM / LogScale CQL using `#event_simpleName` | Falcon sensor telemetry (ProcessRollup2, ImageHash, ClassifiedModuleLoad, AsepValueUpdate, ScheduledTaskRegistered, etc.); third-party cloud logs ingested into NG-SIEM |
| Microsoft Sentinel | KQL | Defender for Endpoint `Device*` tables, `SecurityEvent`, `Syslog`, `AuditLogs`, `SigninLogs`, `AzureActivity`, `AWSCloudTrail`, `GCPAuditLogs` |
| Elastic | ES\|QL (and EQL for sequences) on ECS fields | Elastic Defend / Sysmon via Winlogbeat, Auditbeat/Elastic Agent for Linux, cloud integrations (`aws.cloudtrail`, `azure.*`, `gcp.audit`) |

**Notes**

- Index names, sourcetypes and table names vary by deployment; replace `index=edr`, `logs-*` and similar with your own.
- CrowdStrike field names below reflect Falcon telemetry (`ImageFileName`, `CommandLine`, `TargetFileName`, `ParentBaseFileName`). Fields for Event Search (legacy) differ slightly.
- Queries are hunting starting points, not tuned detections. Expect noise in the first pass; the outlier-review step is where the value is.
- Hunts 1–8 are technique hunts requested explicitly. Hunts 9–16 cover the top 25 techniques used by the groups most active against insurance, financial services and distribution companies (see [Threat landscape](threat-landscape-and-top-25-techniques.md)).

---

[← Collection index](README.md) · [Repository home](../README.md)
