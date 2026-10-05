# H-16 Discovery and lateral movement (techniques 22-23)

**Hypothesis:** An operator is mapping Active Directory and cloud tenants with tools like AdFind, ADExplorer and SharpHound, then moving between hosts over RDP, SMB/PsExec and WinRM along paths that never occurred before.

**Data sources:** EDR process telemetry; Windows Security 4624 (logon types 3 and 10), 4648, 7045 (PSEXESVC); Defender for Identity (`IdentityQueryEvents`, `IdentityLogonEvents`); Falcon `ProcessRollup2`, `UserLogon`, Falcon Identity Protection; Elastic `logs-system.security-*`.

**Steps**

1. Run 16A for AD and trust discovery tools and commands; any SharpHound/AdFind run by a non-admin, or from a server, is high-signal.
2. Run 16B for first-seen source → destination admin logons (RDP and network logons by privileged accounts) and PsExec-style service creation.
3. Map the chain: initial host → discovery → first lateral hop → domain controller / vCenter / backup server. Scattered Spider and ransomware affiliates go straight for hypervisors and backups.

**Query 16A: AD and trust discovery**

Splunk

```
| tstats summariesonly=t count min(_time) as first_seen values(Processes.process) as cmds from datamodel=Endpoint.Processes
  where Processes.process_name IN ("adfind.exe","ADExplorer*.exe","SharpHound.exe","dsquery.exe","nltest.exe","net.exe","net1.exe","powershell.exe")
    (Processes.process IN ("*objectcategory*","*trustdmp*","*domain_trusts*","*dclist*","*-c All*","*CollectionMethod*","*group*domain admins*","*group*enterprise admins*","*Get-ADComputer*-Filter*","*Get-ADUser*-Filter*","*Invoke-BloodHound*","*-snapshot*") OR Processes.process_name IN ("adfind.exe","ADExplorer*.exe","SharpHound.exe"))
  by Processes.dest Processes.user Processes.process_name
| convert ctime(first_seen)
```

CrowdStrike

```
#event_simpleName=ProcessRollup2
| FileName=/^(adfind|ADExplorer.*|SharpHound|dsquery|nltest|net1?|powershell)\.exe$/i
| FileName=/^(adfind|ADExplorer.*|SharpHound)\.exe$/i OR CommandLine=/(objectcategory|trustdmp|domain_trusts|dclist|-c\s+All|CollectionMethod|group\s+"?(domain|enterprise)\s+admins|Get-AD(Computer|User).*-Filter|Invoke-BloodHound|-snapshot)/i
| groupBy([ComputerName, UserName, FileName, CommandLine], function=[count(), min(@timestamp, as=FirstSeen)])
```

KQL

```
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("adfind.exe","SharpHound.exe") or FileName startswith "ADExplorer"
   or (FileName in~ ("dsquery.exe","nltest.exe","net.exe","net1.exe","powershell.exe") and ProcessCommandLine matches regex @"(?i)(objectcategory|trustdmp|domain_trusts|dclist|-c\s+All|CollectionMethod|group\s+""?(domain|enterprise)\s+admins|Get-AD(Computer|User).*-Filter|Invoke-BloodHound|-snapshot)")
| summarize Count = count(), FirstSeen = min(Timestamp), Cmds = make_set(ProcessCommandLine, 10) by DeviceName, AccountName, FileName
| order by FirstSeen desc
```

Elastic (ES|QL)

```
FROM logs-endpoint.events.process-*
| WHERE event.type == "start"
| WHERE TO_LOWER(process.name) IN ("adfind.exe","sharphound.exe") OR TO_LOWER(process.name) LIKE "adexplorer*"
   OR (TO_LOWER(process.name) IN ("dsquery.exe","nltest.exe","net.exe","net1.exe","powershell.exe") AND process.command_line RLIKE """(?i).*(objectcategory|trustdmp|domain_trusts|dclist|-c\s+All|CollectionMethod|group\s+"?(domain|enterprise)\s+admins|Get-AD(Computer|User).*-Filter|Invoke-BloodHound|-snapshot).*""")
| STATS c = COUNT(*), first_seen = MIN(@timestamp), cmds = VALUES(process.command_line) BY host.name, user.name, process.name
```

**Query 16B: first-seen admin logon paths and PsExec-style services**

Splunk

```
index=wineventlog source="WinEventLog:Security" EventCode=4624 Logon_Type IN (3,10) Account_Name IN ("*adm*","*admin*","*svc*") NOT Account_Name="*$"
| stats min(_time) as first_seen count by Account_Name Source_Network_Address host Logon_Type
| where first_seen > relative_time(now(), "-7d")
| append [search index=wineventlog source="WinEventLog:System" EventCode=7045 (Service_Name="PSEXESVC" OR Service_File_Name="*\\ADMIN$\\*" OR Service_File_Name="*%COMSPEC%*") | stats min(_time) as first_seen count by host Service_Name Service_File_Name]
| convert ctime(first_seen)
```

CrowdStrike

```
#event_simpleName=UserLogon LogonType=/^(3|10)$/ UserName=/(adm|admin|svc)/i
| groupBy([UserName, RemoteAddressIP4, ComputerName, LogonType], function=[min(@timestamp, as=FirstSeen), count()])
| test(FirstSeen > (now() - duration("7d")))
```

KQL

```
let lookback = DeviceLogonEvents
| where Timestamp between (ago(37d) .. ago(7d)) and LogonType in ("RemoteInteractive","Network") and AccountName matches regex @"(?i)(adm|admin|svc)"
| distinct AccountName, RemoteIP, DeviceName;
DeviceLogonEvents
| where Timestamp > ago(7d) and ActionType == "LogonSuccess" and LogonType in ("RemoteInteractive","Network") and AccountName matches regex @"(?i)(adm|admin|svc)"
| join kind=leftanti lookback on AccountName, RemoteIP, DeviceName
| summarize FirstSeen = min(Timestamp), Count = count() by AccountName, RemoteIP, RemoteDeviceName, DeviceName, LogonType
| order by FirstSeen desc
```

Elastic (ES|QL)

```
FROM logs-system.security-*
| WHERE event.code == "4624" AND winlog.logon.type IN ("Network","RemoteInteractive") AND user.name RLIKE """(?i).*(adm|admin|svc).*""" AND NOT ENDS_WITH(user.name, "$")
| STATS first_seen = MIN(@timestamp), c = COUNT(*) BY user.name, source.ip, host.name, winlog.logon.type
| WHERE first_seen > NOW() - 7 days
| SORT first_seen DESC
```

Adjust the account-name pattern to your privileged-account naming convention, or join to a list of Tier 0/1 accounts.

**Common false positives:** vulnerability scanners, admin jump hosts, SCCM client push, newly provisioned servers. A workstation logging into a domain controller or vCenter for the first time is always worth a look.

---

[← Collection index](README.md) · [Repository home](../README.md)
