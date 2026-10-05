# H-15 — Credential access: LSASS, NTDS.dit and credential stores (techniques 19–21)

**Hypothesis:** The intruder is harvesting credentials by dumping LSASS memory, extracting `NTDS.dit` (via `ntdsutil`, shadow copies or DCSync), and searching file shares, wikis and password vaults for stored secrets.

**Data sources:** Sysmon EID 10 (process access) and EID 1; Security 4662 (directory service access, with auditing on the domain object), 4688; Falcon `ProcessRollup2` plus credential-theft detections; Defender for Endpoint `DeviceProcessEvents`, `DeviceEvents`, Defender for Identity alerts; Elastic Defend `api`/`process` events; SharePoint/Confluence audit logs.

**Steps**

1. Run 15A for LSASS dumping tools and techniques (`comsvcs.dll MiniDump`, `procdump -ma lsass`, `rundll32` with `#24`, non-standard processes opening LSASS with read access).
2. Run 15B for NTDS extraction: `ntdsutil` IFM, `vssadmin create shadow` on DCs, copies from `HarddiskVolumeShadowCopy`, `reg save HKLM\SYSTEM`, and DCSync (4662 with replication GUIDs by non-DC accounts).
3. Run 15C for credential hunting in files and vaults.
4. Any hit on a domain controller means assuming full domain compromise: plan a double `krbtgt` reset and Tier 0 credential rotation with IR.

**Query 15A — LSASS dumping**

Splunk

```
(index=sysmon EventCode=10 TargetImage="*\\lsass.exe" GrantedAccess IN ("0x1010","0x1410","0x1438","0x143a","0x1fffff") NOT SourceImage IN ("*\\MsMpEng.exe","*\\CSFalconService.exe","*\\wininit.exe","*\\csrss.exe","*\\svchost.exe","*\\elastic-endpoint.exe"))
OR (index=sysmon EventCode=1 (CommandLine="*comsvcs*MiniDump*" OR CommandLine="*comsvcs*#24*" OR (CommandLine="*procdump*" CommandLine="*lsass*") OR CommandLine="*sekurlsa*" OR CommandLine="*nanodump*"))
| table _time host EventCode SourceImage GrantedAccess Image CommandLine User
```

CrowdStrike

```
#event_simpleName=ProcessRollup2
| CommandLine=/(comsvcs(\.dll)?[\s,]+(MiniDump|#24)|procdump.*lsass|sekurlsa|nanodump|lsassy|-ma\s+lsass)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```

KQL

```
union
(DeviceProcessEvents | where Timestamp > ago(30d)
 | where ProcessCommandLine matches regex @"(?i)(comsvcs(\.dll)?[\s,]+(MiniDump|#24)|procdump.*lsass|sekurlsa|nanodump|lsassy|-ma\s+lsass)"
 | project Timestamp, DeviceName, AccountName, Actor = InitiatingProcessFileName, Detail = ProcessCommandLine),
(DeviceEvents | where Timestamp > ago(30d) and ActionType == "OpenProcessApiCall" and FileName =~ "lsass.exe"
 | where InitiatingProcessFileName !in~ ("MsMpEng.exe","CSFalconService.exe","svchost.exe","wininit.exe","csrss.exe")
 | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, Actor = InitiatingProcessFileName, Detail = tostring(AdditionalFields))
```

Elastic (ES|QL)

```
FROM logs-endpoint.events.api-*, logs-endpoint.events.process-*
| WHERE (process.Ext.api.name IN ("OpenProcess","ReadProcessMemory","MiniDumpWriteDump") AND TO_LOWER(Target.process.name) == "lsass.exe" AND NOT TO_LOWER(process.name) IN ("msmpeng.exe","csfalconservice.exe","svchost.exe","wininit.exe","csrss.exe"))
   OR process.command_line RLIKE """(?i).*(comsvcs(\.dll)?[\s,]+(MiniDump|#24)|procdump.*lsass|sekurlsa|nanodump|lsassy|-ma\s+lsass).*"""
| KEEP @timestamp, host.name, user.name, process.name, process.command_line, process.Ext.api.name
```

**Query 15B — NTDS.dit extraction and DCSync**

Splunk

```
(index=sysmon EventCode=1 (CommandLine="*ntdsutil*ifm*" OR CommandLine="*ac i ntds*" OR (CommandLine="*vssadmin*" CommandLine="*create shadow*") OR CommandLine="*HarddiskVolumeShadowCopy*ntds.dit*" OR (CommandLine="*reg*save*" CommandLine="*hklm\\system*") OR CommandLine="*diskshadow*"))
OR (index=wineventlog EventCode=4662 (Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*89e95b76-444d-4c62-991a-0facbeda640c*") NOT Account_Name="*$")
| table _time host EventCode Account_Name CommandLine Properties
```

CrowdStrike

```
#event_simpleName=ProcessRollup2
| CommandLine=/(ntdsutil.*(ifm|ac\s+i\s+ntds)|vssadmin.*create\s+shadow|HarddiskVolumeShadowCopy.*ntds\.dit|reg(\.exe)?\s+save\s+hklm\\(system|sam|security)|diskshadow|secretsdump|DCSync)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```

KQL

```
union
(DeviceProcessEvents | where Timestamp > ago(30d)
 | where ProcessCommandLine matches regex @"(?i)(ntdsutil.*(ifm|ac\s+i\s+ntds)|vssadmin.*create\s+shadow|HarddiskVolumeShadowCopy.*ntds\.dit|reg(\.exe)?\s+save\s+hklm\\(system|sam|security)|diskshadow|secretsdump)"
 | project TimeGenerated = Timestamp, Computer = DeviceName, Account = AccountName, Detail = ProcessCommandLine),
(SecurityEvent | where TimeGenerated > ago(30d) and EventID == 4662
 | where Properties has_any ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2","1131f6ad-9c07-11d1-f79f-00c04fc2dcd2","89e95b76-444d-4c62-991a-0facbeda640c")
 | where SubjectUserName !endswith "$"
 | project TimeGenerated, Computer, Account = SubjectUserName, Detail = "Directory replication (DCSync) requested")
```

Elastic (ES|QL)

```
FROM logs-endpoint.events.process-*, logs-system.security-*
| WHERE process.command_line RLIKE """(?i).*(ntdsutil.*(ifm|ac\s+i\s+ntds)|vssadmin.*create\s+shadow|HarddiskVolumeShadowCopy.*ntds\.dit|reg(\.exe)?\s+save\s+hklm\\(system|sam|security)|diskshadow|secretsdump).*"""
   OR (event.code == "4662" AND winlog.event_data.Properties RLIKE """.*(1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c).*""" AND NOT ENDS_WITH(user.name, "$"))
| KEEP @timestamp, host.name, user.name, event.code, process.command_line
```

**Query 15C — credential hunting in files and stores**

Splunk: `index=sysmon EventCode=1 (CommandLine="*findstr*/si*pass*" OR CommandLine="*Select-String*-Pattern*pass*" OR CommandLine="*dir*/s*pass*" OR CommandLine="*.kdbx*" OR CommandLine="*unattend.xml*" OR CommandLine="*cmdkey*/list*" OR CommandLine="*vaultcmd*" OR CommandLine="*Login Data*" OR CommandLine="*SharpChrome*" OR CommandLine="*LaZagne*") | stats count values(CommandLine) by host User`

CrowdStrike: `#event_simpleName=ProcessRollup2 | CommandLine=/(findstr.*\/si.*pass|Select-String.*-Pattern.*pass|dir.*\/s.*pass|\.kdbx|unattend\.xml|cmdkey.*\/list|vaultcmd|Login Data|SharpChrome|LaZagne|SharpDPAPI)/i | groupBy([ComputerName, UserName, CommandLine], function=count())`

KQL: `DeviceProcessEvents | where Timestamp > ago(30d) | where ProcessCommandLine matches regex @"(?i)(findstr.*/si.*pass|Select-String.*-Pattern.*pass|dir.*/s.*pass|\.kdbx|unattend\.xml|cmdkey.*/list|vaultcmd|Login Data|SharpChrome|LaZagne|SharpDPAPI)" | summarize count(), make_set(ProcessCommandLine, 10) by DeviceName, AccountName`

Elastic ES|QL: `FROM logs-endpoint.events.process-* | WHERE process.command_line RLIKE """(?i).*(findstr.*/si.*pass|Select-String.*-Pattern.*pass|dir.*/s.*pass|\.kdbx|unattend\.xml|cmdkey.*/list|vaultcmd|Login Data|SharpChrome|LaZagne|SharpDPAPI).*""" | STATS c = COUNT(*), cmds = VALUES(process.command_line) BY host.name, user.name`

Also review SharePoint/Confluence search audit logs for queries like `password`, `vpn`, `MFA`, `vCenter`, `CyberArk`, `break glass` from a single user in a short window — a recurring Scattered Spider step.

**Common false positives:** backup software creating shadow copies on DCs, Azure AD Connect (legitimate DCSync — allowlist its `MSOL_` account), EDR/memory-scanning agents opening LSASS.

---

[← Collection index](README.md) · [Repository home](../README.md)
