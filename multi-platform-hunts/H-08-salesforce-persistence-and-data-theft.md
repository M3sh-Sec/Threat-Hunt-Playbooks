# H-08 — Salesforce persistence and data theft

**Hypothesis:** A threat actor has gained persistent API access to our Salesforce org by tricking a user into authorizing a malicious connected app (often a modified Data Loader approved through the OAuth device-code flow), or by abusing OAuth tokens of a trusted third-party integration, and is using that access to bulk-export customer/policyholder records and mine them for secrets.

**Why this matters for insurers:** [Google GTIG documented UNC6040](https://cloud.google.com/blog/topics/threat-intelligence/voice-phishing-data-extortion) calling employees as IT support and walking them through approving a modified Data Loader app, then exporting Salesforce data immediately. GTIG also observed the same actor moving on to Okta and Microsoft 365 and [operating mostly from Mullvad VPN addresses](https://cloud.google.com/blog/topics/threat-intelligence/unc6040-proactive-hardening-recommendations). A second campaign (UNC6395) abused stolen Salesloft Drift OAuth tokens; [Mitiga's write-up](https://www.mitiga.io/blog/shinyhunters-and-unc6395-inside-the-salesforce-and-salesloft-breaches) covers both. Insurers including Allianz and Aflac were among [the group's 2025 victims](https://specopssoft.com/blog/top-threat-actors-targeting-insurance-industry/).

**ATT&CK:** T1566.004 Spearphishing Voice, T1528 Steal Application Access Token, T1550.001 Application Access Token, T1098 Account Manipulation, T1530 Data from Cloud Storage, T1213 Data from Information Repositories, T1552.001 Credentials in Files, T1567 Exfiltration over Web Service.

**Data sources**

| Source | Contents | Splunk | Sentinel | Elastic | CrowdStrike |
| --- | --- | --- | --- | --- | --- |
| LoginHistory / Login event log | Login type, application (connected app), source IP, user agent, status | `sfdc:loginhistory`, `sfdc:logfile EVENT_TYPE=Login` | `SalesforceServiceCloud_CL` (or V2 table) | `logs-salesforce.login-*` | NG-SIEM Salesforce connector |
| Event Monitoring (API, RestApi, BulkApi, BulkApi2, ReportExport, URI) | Objects queried, rows processed, client | `sfdc:logfile` | `SalesforceServiceCloud_CL` | `logs-salesforce.apex-*` | NG-SIEM |
| Real-Time Event Monitoring (Shield): `ApiEvent`, `BulkApiResultEvent`, `ReportEvent`, `LoginEvent` | Includes SOQL `Query` text and `RowsProcessed` | via Event Monitoring Analytics / streaming | custom table | custom ingest | NG-SIEM |
| Setup Audit Trail | Connected app creation/edits, permission changes, user creation | `sfdc:setupaudittrail` | `SalesforceServiceCloud_CL` | `logs-salesforce.setupaudittrail-*` | NG-SIEM |
| Connected App OAuth Usage / `OauthToken` object | Which apps hold tokens for which users | Scheduled SOQL pull | — | — | — |

Salesforce field names differ across connectors; queries below use Event Log File names (`EVENT_TYPE`, `USER_ID`, `CLIENT_IP`, `ROWS_PROCESSED`, `ENTITY_NAME`, `URI`) and LoginHistory names (`Application`, `LoginType`, `SourceIp`, `Browser`).

**Steps**

1. Export the list of connected apps currently holding OAuth tokens (Setup → Connected Apps OAuth Usage). Anything unknown, any Data Loader variant with a non-standard name, and any third-party integration you don't own a contract for is a lead.
2. Run 8A for OAuth / connected-app logins by application name, new IPs, VPN/hosting ASNs (Mullvad, Tor exits) and the device-code flow.
3. Run 8B for bulk export: high `ROWS_PROCESSED`, BulkApi jobs, and API queries against `Account`, `Contact`, `Case`, `Opportunity`, `User`, policy/claim custom objects.
4. Run 8C on Setup Audit Trail for persistence: new connected apps, OAuth policy changes, "API Enabled" / "Modify All Data" / "View All Data" granted, new users, login-IP range relaxations.
5. If Shield is available, run 8D on `ApiEvent.Query` for secret-hunting SOQL (`AKIA`, `password`, `secret`, `token`, `snowflake`) — UNC6395's hallmark — and for deletion of bulk query jobs.
6. Correlate the Salesforce user with identity provider logs (Okta/Entra) for the preceding help-desk call, MFA reset or device-code approval (Hunt 5, Hunt 9).
7. Containment: revoke the app's tokens, block it via API Access Control (allowlist connected apps), remove "API Enabled" from non-essential profiles, rotate any secrets found in records.

**Query 8A — OAuth and connected-app logins from unknown apps or new networks**

Splunk

```
index=salesforce sourcetype=sfdc:loginhistory Status=Success
  LoginType IN ("Remote Access 2.0","Remote Access Client","OAuth Device Flow","Other Apex API","Partner Product")
| eval app=coalesce(Application,"(none)")
| search NOT app IN ("Salesforce for iOS","Salesforce for Android","Salesforce CLI","<your approved integrations>")
| iplocation SourceIp
| stats count min(_time) as first_seen dc(SourceIp) as ips values(SourceIp) as src values(Country) as countries values(Browser) as agents by UserId app LoginType
| convert ctime(first_seen)
| sort first_seen desc
```

CrowdStrike (NG-SIEM)

```
#Vendor="salesforce" event.category=authentication event.outcome=success
| Vendor.LoginType=/Remote Access|OAuth|Device|Apex API|Partner/i
| App := Vendor.Application
| !in(field=App, values=["Salesforce for iOS","Salesforce for Android","Salesforce CLI"])
| asn(source.ip) | ipLocation(source.ip)
| groupBy([user.name, App, Vendor.LoginType], function=[count(), min(@timestamp, as=FirstSeen), collect([source.ip, source.ip.asn.org, source.ip.country, user_agent.original], limit=10)])
| sort(FirstSeen, order=desc)
```

KQL

```
SalesforceServiceCloud_CL
| where TimeGenerated > ago(30d)
| where EventType_s == "Login" or isnotempty(LoginType_s)
| where LoginType_s has_any ("Remote Access","OAuth","Device","Apex API","Partner") and LoginStatus_s in ("LOGIN_NO_ERROR","Success")
| extend App = coalesce(Application_s, ConnectedAppId_s), Ip = coalesce(ClientIp_s, SourceIp_s)
| where App !in ("Salesforce for iOS","Salesforce for Android","Salesforce CLI")
| summarize Count = count(), FirstSeen = min(TimeGenerated), IPs = make_set(Ip, 20), Agents = make_set(UserAgent_s, 5) by UserId_s, App, LoginType_s
| order by FirstSeen desc
```

Elastic (ES|QL)

```
FROM logs-salesforce.login-*
| WHERE event.outcome == "success"
| WHERE salesforce.login.login_type RLIKE """.*(Remote Access|OAuth|Device|Apex API|Partner).*"""
| WHERE NOT salesforce.login.application IN ("Salesforce for iOS","Salesforce for Android","Salesforce CLI")
| STATS c = COUNT(*), first_seen = MIN(@timestamp), ips = VALUES(source.ip), asns = VALUES(source.as.organization.name), agents = VALUES(user_agent.original)
    BY user.email, salesforce.login.application, salesforce.login.login_type
| SORT first_seen DESC
```

**Query 8B — bulk or anomalous record export**

Splunk

```
index=salesforce sourcetype=sfdc:logfile EVENT_TYPE IN (API, RestApi, BulkApi, BulkApi2, ReportExport)
| eval rows=tonumber(coalesce(ROWS_PROCESSED, NUMBER_OF_RECORDS, RECORDS_PROCESSED))
| eval obj=coalesce(ENTITY_NAME, ENTITY_TYPE, mvindex(split(URI,"/"),-1))
| stats sum(rows) as total_rows count as calls dc(obj) as objects values(obj) as objs values(CLIENT_IP) as ips values(USER_AGENT) as agents by USER_ID EVENT_TYPE
| eventstats avg(total_rows) as avg_rows stdev(total_rows) as sd_rows by EVENT_TYPE
| where total_rows > avg_rows + 3*sd_rows OR total_rows > 50000
| sort - total_rows
```

CrowdStrike (NG-SIEM)

```
#Vendor="salesforce" in(field="Vendor.EVENT_TYPE", values=["API","RestApi","BulkApi","BulkApi2","ReportExport"])
| Rows := coalesce([Vendor.ROWS_PROCESSED, Vendor.NUMBER_OF_RECORDS])
| groupBy([user.name, Vendor.EVENT_TYPE], function=[sum(Rows, as=TotalRows), count(as=Calls), collect([Vendor.ENTITY_NAME, source.ip, user_agent.original], limit=20)])
| TotalRows > 50000
| sort(TotalRows, order=desc)
```

KQL

```
SalesforceServiceCloud_CL
| where TimeGenerated > ago(30d) and EventType_s in ("API","RestApi","BulkApi","BulkApi2","ReportExport")
| extend Rows = todouble(coalesce(RowsProcessed_d, NumberOfRecords_d)), Obj = coalesce(EntityName_s, EntityType_s)
| summarize TotalRows = sum(Rows), Calls = count(), Objects = make_set(Obj, 20), IPs = make_set(ClientIp_s, 10), Agents = make_set(UserAgent_s, 5) by UserId_s, EventType_s, bin(TimeGenerated, 1d)
| join kind=leftouter (
    SalesforceServiceCloud_CL | where TimeGenerated between (ago(60d) .. ago(7d)) and EventType_s in ("API","RestApi","BulkApi","BulkApi2","ReportExport")
    | summarize BaselineDaily = sum(todouble(coalesce(RowsProcessed_d, NumberOfRecords_d))) / 53.0 by UserId_s, EventType_s
  ) on UserId_s, EventType_s
| where TotalRows > 10 * coalesce(BaselineDaily, 1000.0) or TotalRows > 50000
| order by TotalRows desc
```

Elastic (ES|QL)

```
FROM logs-salesforce.apex-*
| WHERE event.action IN ("API","RestApi","BulkApi","BulkApi2","ReportExport")
| EVAL rows = TO_DOUBLE(salesforce.apex.rows_processed)
| STATS total_rows = SUM(rows), calls = COUNT(*), objects = VALUES(salesforce.apex.entity_name), ips = VALUES(source.ip), agents = VALUES(user_agent.original)
    BY user.id, event.action, day = DATE_TRUNC(1 day, @timestamp)
| WHERE total_rows > 50000
| SORT total_rows DESC
```

**Query 8C — Setup Audit Trail persistence changes**

Watch these `Action` values: `insertConnectedApplication`, `updateConnectedApplication`, `connectedAppOauthPolicyChange`, `PermSetAssign`, `PermSetEnableUserPerm` (API Enabled, Modify All Data, View All Data, Manage Users, Author Apex), `createduser`, `changedprofileforuser`, `loginIpRangesChanged` / `orgIpRangesChanged`, `changedsessiontimeout`, `namedCredentialCreated`, `remoteSiteCreated`, `certificateCreated`.

Splunk

```
index=salesforce sourcetype=sfdc:setupaudittrail
| search Action IN ("insertConnectedApplication","updateConnectedApplication","connectedAppOauthPolicyChange","PermSetAssign","PermSetEnableUserPerm","createduser","changedprofileforuser","loginIpRangesChanged","orgIpRangesChanged","changedsessiontimeout","namedCredentialCreated","remoteSiteCreated","certificateCreated")
   OR Display="*API Enabled*" OR Display="*Modify All Data*" OR Display="*View All Data*"
| table _time CreatedById CreatedBy.Username Action Section Display DelegateUser
| sort - _time
```

CrowdStrike: `#Vendor="salesforce" Vendor.Section=* | in(field="Vendor.Action", values=["insertConnectedApplication","updateConnectedApplication","connectedAppOauthPolicyChange","PermSetAssign","PermSetEnableUserPerm","createduser","changedprofileforuser","loginIpRangesChanged","orgIpRangesChanged","namedCredentialCreated","remoteSiteCreated","certificateCreated"]) OR Vendor.Display=/API Enabled|Modify All Data|View All Data/ | table([@timestamp, user.name, Vendor.Action, Vendor.Section, Vendor.Display])`

KQL: `SalesforceServiceCloud_CL | where TimeGenerated > ago(30d) and isnotempty(Action_s) | where Action_s in ("insertConnectedApplication","updateConnectedApplication","connectedAppOauthPolicyChange","PermSetAssign","PermSetEnableUserPerm","createduser","changedprofileforuser","loginIpRangesChanged","orgIpRangesChanged","namedCredentialCreated","remoteSiteCreated","certificateCreated") or Display_s has_any ("API Enabled","Modify All Data","View All Data") | project TimeGenerated, CreatedBy_s, Action_s, Section_s, Display_s`

Elastic ES|QL: `FROM logs-salesforce.setupaudittrail-* | WHERE event.action IN ("insertConnectedApplication","updateConnectedApplication","connectedAppOauthPolicyChange","PermSetAssign","PermSetEnableUserPerm","createduser","changedprofileforuser","loginIpRangesChanged","orgIpRangesChanged","namedCredentialCreated","remoteSiteCreated","certificateCreated") OR salesforce.setup_audit_trail.display RLIKE ".*(API Enabled|Modify All Data|View All Data).*" | KEEP @timestamp, user.name, event.action, salesforce.setup_audit_trail.section, salesforce.setup_audit_trail.display`

**Query 8D — secret-hunting SOQL and job cleanup (requires Shield Real-Time Event Monitoring `ApiEvent`)**

Splunk: `index=salesforce sourcetype=sfdc:apievent | regex Query="(?i)(AKIA|ASIA|password|passwd|secret|api[_ ]?key|token|snowflake|BEGIN (RSA|OPENSSH) PRIVATE KEY)" | stats count values(Query) as queries values(SourceIp) as ips by Username Application`

CrowdStrike: `#Vendor="salesforce" Vendor.Query=/(AKIA|ASIA|password|passwd|secret|api[_ ]?key|token|snowflake|PRIVATE KEY)/i | groupBy([user.name, Vendor.Application], function=[count(), collect([Vendor.Query, source.ip], limit=20)])`

KQL: `SalesforceApiEvent_CL | where Query_s matches regex @"(?i)(AKIA|ASIA|password|passwd|secret|api[_ ]?key|token|snowflake|PRIVATE KEY)" | summarize count(), make_set(Query_s, 20), make_set(SourceIp_s, 10) by Username_s, Application_s`

Elastic ES|QL: `FROM logs-salesforce.apievent-* | WHERE salesforce.api_event.query RLIKE """(?i).*(AKIA|ASIA|password|passwd|secret|api[_ ]?key|token|snowflake|PRIVATE KEY).*""" | STATS c = COUNT(*), q = VALUES(salesforce.api_event.query) BY user.name, salesforce.api_event.application`

Also search for bulk query jobs that were created and then deleted by the same user within minutes (BulkApi `DELETE` on `/jobs/query/`), which UNC6395 used to cover its tracks.

**Common false positives:** sanctioned ETL (MuleSoft, Informatica, Fivetran), marketing sync tools, admins running Data Loader for migrations. Approved integrations should run under dedicated integration users with IP restrictions — anything else using Data Loader is worth a call to the user.

---

[← Collection index](README.md) · [Repository home](../README.md)
