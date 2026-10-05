# H-14 Defense evasion: EDR tampering, log clearing and rogue cloud VMs (techniques 16-18)

**Hypothesis:** Before stealing data or deploying ransomware, the operator is blinding us. That can mean disabling or excluding security tools (sometimes with a vulnerable signed driver), clearing event logs, or standing up cloud VMs with no EDR so they can work unseen.

**Data sources:** EDR process and driver-load telemetry (Sysmon EID 1/6, Falcon `ProcessRollup2`/`DriverLoad`, `DeviceProcessEvents`/`DeviceEvents` DriverLoad, Elastic `logs-endpoint.events.library-*`/`process-*`); Windows Security 1102, System 104, Defender Operational 5001/5007; CloudTrail, Azure Activity, GCP Admin Activity.

**Steps**

1. Run 14A for commands that stop/delete security services, add Defender exclusions or disable real-time protection, and for loads of known-vulnerable drivers (check against [loldrivers.io](https://www.loldrivers.io/)).
2. Run 14B for log clearing on Windows and Linux.
3. Run 14C for VMs created by human identities (not automation). CISA reports that Scattered Spider has created cloud VMs to work outside EDR coverage.
4. Any confirmed tampering means the host's telemetry after that point is unreliable; pull a forensic image and widen the hunt to neighboring hosts.

**Query 14A: security tool tampering and vulnerable driver loads**

Splunk

```
(index=sysmon EventCode=1 (CommandLine="*Set-MpPreference*" (CommandLine="*DisableRealtimeMonitoring*" OR CommandLine="*ExclusionPath*" OR CommandLine="*ExclusionProcess*") OR (Image="*\\sc.exe" CommandLine IN ("*stop*","*delete*","*config*disabled*") CommandLine IN ("*WinDefend*","*Sense*","*CSFalcon*","*elastic*","*SentinelAgent*","*Sysmon*") ) OR (CommandLine="*taskkill*" CommandLine IN ("*MsMpEng*","*CSFalconService*","*elastic-agent*"))))
OR (index=sysmon EventCode=6 ImageLoaded IN ("*\\RTCore64.sys","*\\gdrv.sys","*\\dbutil_2_3.sys","*\\procexp152.sys","*\\aswArPot.sys","*\\zam64.sys","*\\truesight.sys","*\\mhyprot2.sys","*\\iqvw64e.sys"))
| table _time host EventCode User Image CommandLine ImageLoaded Hashes
```

CrowdStrike

```
(#event_simpleName=ProcessRollup2 CommandLine=/(Set-MpPreference.*(DisableRealtimeMonitoring|Exclusion(Path|Process|Extension))|sc(\.exe)?\s+(stop|delete|config).*(WinDefend|Sense|CSFalcon|elastic|SentinelAgent|Sysmon)|taskkill.*(MsMpEng|CSFalconService|elastic-agent))/i)
OR (#event_simpleName=DriverLoad FileName=/^(RTCore64|gdrv|dbutil_2_3|procexp152|aswArPot|zam64|truesight|mhyprot2|iqvw64e)\.sys$/i)
| table([@timestamp, ComputerName, #event_simpleName, UserName, FileName, CommandLine, SHA256HashData])
```

KQL

```
union
(DeviceProcessEvents | where Timestamp > ago(30d)
 | where ProcessCommandLine matches regex @"(?i)(Set-MpPreference.*(DisableRealtimeMonitoring|Exclusion(Path|Process|Extension))|sc(\.exe)?\s+(stop|delete|config).*(WinDefend|Sense|CSFalcon|elastic|SentinelAgent|Sysmon)|taskkill.*(MsMpEng|CSFalconService|elastic-agent))"
 | project Timestamp, DeviceName, Kind = "command", Detail = ProcessCommandLine, AccountName),
(DeviceEvents | where Timestamp > ago(30d) and ActionType == "DriverLoad"
 | where FileName in~ ("RTCore64.sys","gdrv.sys","dbutil_2_3.sys","procexp152.sys","aswArPot.sys","zam64.sys","truesight.sys","mhyprot2.sys","iqvw64e.sys")
 | project Timestamp, DeviceName, Kind = "driver", Detail = strcat(FolderPath, " ", SHA256), AccountName = InitiatingProcessAccountName)
| order by Timestamp desc
```

Elastic (ES|QL)

```
FROM logs-endpoint.events.process-*, logs-endpoint.events.library-*
| WHERE process.command_line RLIKE """(?i).*(Set-MpPreference.*(DisableRealtimeMonitoring|Exclusion(Path|Process|Extension))|sc(\.exe)?\s+(stop|delete|config).*(WinDefend|Sense|CSFalcon|elastic|SentinelAgent|Sysmon)|taskkill.*(MsMpEng|CSFalconService|elastic-agent)).*"""
   OR TO_LOWER(dll.name) IN ("rtcore64.sys","gdrv.sys","dbutil_2_3.sys","procexp152.sys","aswarpot.sys","zam64.sys","truesight.sys","mhyprot2.sys","iqvw64e.sys")
| KEEP @timestamp, host.name, user.name, process.command_line, dll.path, dll.hash.sha256
```

**Query 14B: event log clearing**

Splunk: `(index=wineventlog (EventCode=1102 OR (source="WinEventLog:System" EventCode=104))) OR (index=sysmon EventCode=1 (CommandLine="*wevtutil* cl *" OR CommandLine="*Clear-EventLog*" OR CommandLine="*Remove-EventLog*")) OR (index=linux ("history -c" OR "> /var/log/" OR "shred " OR "unset HISTFILE")) | stats count values(CommandLine) by host user EventCode`

CrowdStrike: `(#event_simpleName=ProcessRollup2 CommandLine=/(wevtutil(\.exe)?\s+cl\s|Clear-EventLog|Remove-EventLog|history\s+-c|unset\s+HISTFILE|shred\s+.*\/var\/log|>\s*\/var\/log\/)/i) OR #event_simpleName=EventLogCleared | table([@timestamp, ComputerName, UserName, CommandLine, #event_simpleName])`

KQL: `union (SecurityEvent | where EventID == 1102 | project TimeGenerated, Computer, Detail = "Security log cleared", Account = SubjectUserName), (Event | where EventLog == "System" and EventID == 104 | project TimeGenerated, Computer, Detail = RenderedDescription, Account = UserName), (DeviceProcessEvents | where ProcessCommandLine matches regex @"(?i)(wevtutil(\.exe)?\s+cl\s|Clear-EventLog|Remove-EventLog|history\s+-c|unset\s+HISTFILE|shred\s+.*/var/log|>\s*/var/log/)" | project TimeGenerated = Timestamp, Computer = DeviceName, Detail = ProcessCommandLine, Account = AccountName)`

Elastic ES|QL: `FROM logs-system.security-*, logs-system.system-*, logs-endpoint.events.process-* | WHERE event.code IN ("1102","104") OR process.command_line RLIKE """(?i).*(wevtutil(\.exe)?\s+cl\s|Clear-EventLog|Remove-EventLog|history\s+-c|unset\s+HISTFILE|shred\s+.*/var/log|>\s*/var/log/).*""" | KEEP @timestamp, host.name, user.name, event.code, process.command_line`

**Query 14C: cloud VMs created by human identities**

Splunk: `(index=aws sourcetype=aws:cloudtrail eventName=RunInstances userIdentity.type IN (IAMUser, AssumedRole) NOT userIdentity.arn IN ("*terraform*","*cicd*","*autoscaling*")) OR (index=azure operationName.value="MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE" caller="*@*") OR (index=gcp data.protoPayload.methodName IN ("v1.compute.instances.insert","beta.compute.instances.insert") data.protoPayload.authenticationInfo.principalEmail!="*gserviceaccount.com") | eval actor=coalesce('userIdentity.arn', caller, 'data.protoPayload.authenticationInfo.principalEmail') | stats count min(_time) as first_seen values(sourceIPAddress) values(callerIpAddress) by actor`

CrowdStrike: `(#Vendor="aws" event.action=RunInstances) OR (#Vendor="microsoft" event.action=/virtualMachines\/write/i) OR (#Vendor="google" event.action=/compute\.instances\.insert$/) | user.name!=/terraform|cicd|autoscaling|gserviceaccount/i | groupBy([user.name, event.action], function=[count(), min(@timestamp, as=FirstSeen), collect([source.ip])])`

KQL:

```
union
(AWSCloudTrail | where EventName == "RunInstances" and UserIdentityType in ("IAMUser","AssumedRole") and UserIdentityArn !has_any ("terraform","cicd","autoscaling") | project TimeGenerated, Cloud = "AWS", Actor = UserIdentityArn, SrcIp = SourceIpAddress),
(AzureActivity | where OperationNameValue =~ "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE" and Caller has "@" and ActivityStatusValue in ("Success","Succeeded") | project TimeGenerated, Cloud = "Azure", Actor = Caller, SrcIp = CallerIpAddress),
(GCPAuditLogs | where MethodName has "compute.instances.insert" and PrincipalEmail !endswith "gserviceaccount.com" | project TimeGenerated, Cloud = "GCP", Actor = PrincipalEmail, SrcIp = CallerIp)
| summarize Count = count(), FirstSeen = min(TimeGenerated), IPs = make_set(SrcIp, 10) by Cloud, Actor
| order by FirstSeen desc
```

Elastic ES|QL: `FROM logs-aws.cloudtrail-*, logs-azure.activitylogs-*, logs-gcp.audit-* | WHERE event.action IN ("RunInstances","v1.compute.instances.insert","beta.compute.instances.insert") OR TO_LOWER(event.action) LIKE "*virtualmachines/write*" | WHERE NOT user.name RLIKE """(?i).*(terraform|cicd|autoscaling|gserviceaccount).*""" | STATS c = COUNT(*), first_seen = MIN(@timestamp), ips = VALUES(source.ip) BY event.action, user.name`

**Common false positives:** EDR upgrades and reinstall scripts, golden-image builds, developers launching test VMs. VMs created from a recently reset identity, in an unused region, or with public IPs and RDP/SSH open are the priority.

---

[← Collection index](README.md) · [Repository home](../README.md)
