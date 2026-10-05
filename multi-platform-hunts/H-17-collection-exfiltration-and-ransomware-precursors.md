# H-17 Collection, exfiltration and ransomware precursors (techniques 24-25)

**Hypothesis:** The adversary is staging data from file shares, SharePoint/OneDrive or Confluence and sending it to cloud storage with tools like rclone or MEGA, and preparing for encryption by deleting shadow copies, disabling recovery and touching ESXi hosts.

**Data sources:** EDR process and network telemetry; proxy/firewall egress logs with byte counts; M365 Unified Audit Log (`OfficeActivity` in Sentinel, `o365:management:activity` in Splunk, `logs-o365.audit-*` in Elastic); ESXi syslog (`shell.log`, `hostd.log`, `auth.log`); vCenter events.

**Steps**

1. Run 17A for exfiltration tooling and uploads to file-sharing services.
2. Run 17B for mass downloads from SharePoint/OneDrive by a single user (thresholds relative to that user's baseline).
3. Run 17C for ransomware precursors on Windows and ESXi. A hit here means an incident, not a hunt. Page IR.
4. Correlate egress volume per host with Hunt 11 (RMM tools are often the exfil channel) and Hunt 14 (tamper events just before exfil).

**Query 17A: exfiltration tools and file-sharing destinations**

Splunk

```
(index=sysmon EventCode=1 (Image IN ("*\\rclone.exe","*\\MEGAcmd*.exe","*\\megasync.exe","*\\restic.exe","*\\WinSCP.exe","*\\pscp.exe") OR CommandLine IN ("* copy * remote:*","*--config*rclone.conf*","*mega:*","*curl*-T *","*curl*--upload-file*")))
OR (index=proxy dest IN ("*mega.nz","*mega.io","*transfer.sh","*file.io","*gofile.io","*temp.sh","*anonfiles*","*sendspace.com","*filemail.com") bytes_out>10000000)
| stats sum(bytes_out) as bytes_out values(CommandLine) as cmds values(dest) as dests by host user
| eval MB_out=round(bytes_out/1024/1024,1)
| sort - MB_out
```

CrowdStrike

```
(#event_simpleName=ProcessRollup2 (FileName=/^(rclone|MEGAcmd.*|megasync|restic|WinSCP|pscp)\.exe$/i OR CommandLine=/(\scopy\s.*\s\w+:|rclone\.conf|mega:|curl.*(-T\s|--upload-file))/i))
OR (#event_simpleName=DnsRequest DomainName=/(mega\.nz|mega\.io|transfer\.sh|file\.io|gofile\.io|temp\.sh|sendspace\.com|filemail\.com)$/i)
| groupBy([ComputerName, UserName, #event_simpleName], function=[count(), collect([FileName, CommandLine, DomainName], limit=20)])
```

KQL

```
union
(DeviceProcessEvents | where Timestamp > ago(30d)
 | where FileName in~ ("rclone.exe","megasync.exe","restic.exe","WinSCP.exe","pscp.exe") or FileName startswith "MEGAcmd" or ProcessVersionInfoOriginalFileName =~ "rclone.exe"
    or ProcessCommandLine matches regex @"(?i)(\scopy\s.*\s\w+:|rclone\.conf|mega:|curl.*(-T\s|--upload-file))"
 | project Timestamp, DeviceName, AccountName, Detail = ProcessCommandLine),
(DeviceNetworkEvents | where Timestamp > ago(30d)
 | where RemoteUrl matches regex @"(?i)(mega\.nz|mega\.io|transfer\.sh|file\.io|gofile\.io|temp\.sh|sendspace\.com|filemail\.com)"
 | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, Detail = strcat(InitiatingProcessFileName, " -> ", RemoteUrl))
| summarize Count = count(), FirstSeen = min(Timestamp), Details = make_set(Detail, 20) by DeviceName, AccountName
```

Elastic (ES|QL)

```
FROM logs-endpoint.events.process-*, logs-endpoint.events.network-*
| WHERE TO_LOWER(process.name) IN ("rclone.exe","megasync.exe","restic.exe","winscp.exe","pscp.exe") OR TO_LOWER(process.pe.original_file_name) == "rclone.exe"
   OR process.command_line RLIKE """(?i).*(\scopy\s.*\s\w+:|rclone\.conf|mega:|curl.*(-T\s|--upload-file)).*"""
   OR dns.question.name RLIKE """.*(mega\.nz|mega\.io|transfer\.sh|file\.io|gofile\.io|temp\.sh|sendspace\.com|filemail\.com)"""
| STATS c = COUNT(*), first_seen = MIN(@timestamp), cmds = VALUES(process.command_line), domains = VALUES(dns.question.name) BY host.name, user.name
```

**Query 17B: mass download from SharePoint/OneDrive**

Splunk: `index=o365 sourcetype=o365:management:activity Workload IN (SharePoint, OneDrive) Operation IN (FileDownloaded, FileSyncDownloadedFull, FileAccessed) | bin _time span=1h | stats count dc(ObjectId) as files values(ClientIP) as ips by UserId _time | eventstats avg(files) as avg_files stdev(files) as sd by UserId | where files > 500 OR files > avg_files + 4*sd`

CrowdStrike: `#Vendor="microsoft" in(field="event.action", values=["FileDownloaded","FileSyncDownloadedFull"]) | bucket(span=1h, field=[user.name], function=[count(Vendor.ObjectId, distinct=true, as=Files), collect([source.ip])]) | Files > 500`

KQL:

```
OfficeActivity
| where TimeGenerated > ago(30d) and OfficeWorkload in ("SharePoint","OneDrive") and Operation in ("FileDownloaded","FileSyncDownloadedFull")
| summarize Files = dcount(OfficeObjectId), IPs = make_set(ClientIP, 5), Sites = make_set(Site_Url, 5) by UserId, bin(TimeGenerated, 1h)
| join kind=leftouter (OfficeActivity | where TimeGenerated between (ago(60d) .. ago(30d)) and Operation in ("FileDownloaded","FileSyncDownloadedFull") | summarize Baseline = count() / (30.0 * 24) by UserId) on UserId
| where Files > 500 or Files > 20 * coalesce(Baseline, 1.0)
| order by Files desc
```

Elastic ES|QL: `FROM logs-o365.audit-* | WHERE event.action IN ("FileDownloaded","FileSyncDownloadedFull") | STATS files = COUNT_DISTINCT(o365.audit.ObjectId), ips = VALUES(source.ip) BY user.id, hour = DATE_TRUNC(1 hour, @timestamp) | WHERE files > 500 | SORT files DESC`

**Query 17C: ransomware precursors (Windows and ESXi)**

Splunk

```
(index=sysmon EventCode=1 (CommandLine="*vssadmin*delete*shadows*" OR CommandLine="*wmic*shadowcopy*delete*" OR CommandLine="*bcdedit*recoveryenabled*no*" OR CommandLine="*bcdedit*bootstatuspolicy*ignoreallfailures*" OR CommandLine="*wbadmin*delete*" OR CommandLine="*Win32_ShadowCopy*Delete*"))
OR (index=esxi ("esxcli vm process kill" OR "vim-cmd vmsvc/power.off" OR "vim-cmd vmsvc/getallvms" OR "esxcli system settings advanced set -o /User/execInstalledOnly -i 0" OR "SSH access has been enabled" OR "encrypt"))
| table _time host user CommandLine _raw
```

CrowdStrike

```
#event_simpleName=ProcessRollup2
| CommandLine=/(vssadmin.*delete\s+shadows|wmic.*shadowcopy.*delete|bcdedit.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|wbadmin.*delete|Win32_ShadowCopy.*Delete|esxcli\s+vm\s+process\s+kill|vim-cmd\s+vmsvc\/(power\.off|getallvms)|execInstalledOnly\s+-i\s+0)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```

KQL

```
union
(DeviceProcessEvents | where Timestamp > ago(30d)
 | where ProcessCommandLine matches regex @"(?i)(vssadmin.*delete\s+shadows|wmic.*shadowcopy.*delete|bcdedit.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|wbadmin.*delete|Win32_ShadowCopy.*Delete)"
 | project TimeGenerated = Timestamp, Host = DeviceName, Account = AccountName, Detail = ProcessCommandLine),
(Syslog | where TimeGenerated > ago(30d) and (HostName has "esx" or ProcessName in ("shell","hostd","sshd"))
 | where SyslogMessage has_any ("esxcli vm process kill","vim-cmd vmsvc/power.off","vim-cmd vmsvc/getallvms","execInstalledOnly -i 0","SSH access has been enabled")
 | project TimeGenerated, Host = HostName, Account = "", Detail = SyslogMessage)
| order by TimeGenerated desc
```

Elastic (ES|QL)

```
FROM logs-endpoint.events.process-*, logs-vmware.esxi-*, logs-system.syslog-*
| WHERE process.command_line RLIKE """(?i).*(vssadmin.*delete\s+shadows|wmic.*shadowcopy.*delete|bcdedit.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|wbadmin.*delete|Win32_ShadowCopy.*Delete).*"""
   OR message RLIKE """.*(esxcli vm process kill|vim-cmd vmsvc/power\.off|vim-cmd vmsvc/getallvms|execInstalledOnly -i 0|SSH access has been enabled).*"""
| KEEP @timestamp, host.name, user.name, process.command_line, message
```

**Common false positives:** backup software managing shadow copies, approved data migrations, vSphere admins running maintenance scripts. Any shadow-copy deletion outside a backup tool's own process tree should be treated as an incident.

---

[← Collection index](README.md) · [Repository home](../README.md)
