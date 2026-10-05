# H-12 — Living-off-the-land execution: PowerShell, cmd and WMI (techniques 9–11)

**Hypothesis:** An operator is running hands-on-keyboard commands through PowerShell (encoded commands, download cradles, AMSI bypasses), `cmd.exe` and WMI/Impacket-style remote execution, which stand out from admin scripts by their encoding, parent process and destination.

**Data sources:** Sysmon EID 1; PowerShell Script Block Logging (EID 4104) and Module Logging; Security 4688 with command line; Falcon `ProcessRollup2`, `ScriptControlScanTelemetry`/`CommandHistory`; `DeviceProcessEvents`, `DeviceEvents` (PowerShellCommand, AmsiScriptDetection); Elastic `logs-endpoint.events.process-*`, `logs-windows.powershell_operational-*`.

**Steps**

1. Run 12A for suspicious PowerShell command lines and script blocks; stack by parent process and user.
2. Run 12B for WMI and Impacket-style remote execution (`wmiprvse.exe` spawning shells, output redirected to `\\127.0.0.1\ADMIN$`).
3. Decode `-enc` payloads (base64 UTF-16LE) and extract URLs/IPs for pivoting.
4. Escalate anything run by a recently reset account (Hunt 9) or launched via an RMM tool (Hunt 11).

**Query 12A — suspicious PowerShell**

Indicators: `-enc`, `-EncodedCommand`, `-w hidden`, `-nop`, `IEX`, `Invoke-Expression`, `DownloadString`, `DownloadFile`, `Net.WebClient`, `Invoke-WebRequest`, `FromBase64String`, `AmsiUtils`, `amsiInitFailed`, `Reflection.Assembly::Load`, `Invoke-Mimikatz`, `Get-ADComputer`, `-bxor`.

Splunk

```
(index=sysmon EventCode=1 Image IN ("*\\powershell.exe","*\\pwsh.exe")) OR (index=wineventlog source="*PowerShell/Operational" EventCode=4104)
| eval text=coalesce(CommandLine, ScriptBlockText)
| regex text="(?i)(-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|-w(indowstyle)?\s+hid|\bIEX\b|Invoke-Expression|DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|FromBase64String|AmsiUtils|amsiInitFailed|Reflection\.Assembly\]::Load|Invoke-Mimikatz|-bxor)"
| stats count min(_time) as first_seen values(ParentImage) as parents values(host) as hosts by user text
| convert ctime(first_seen)
```

CrowdStrike

```
#event_simpleName=ProcessRollup2 FileName=/^(powershell|pwsh)\.exe$/i
| CommandLine=/(-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{20,}|-w(indowstyle)?\s+hid|\bIEX\b|Invoke-Expression|DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|FromBase64String|AmsiUtils|amsiInitFailed|Reflection\.Assembly\]::Load|Invoke-Mimikatz|-bxor)/i
| groupBy([ComputerName, UserName, ParentBaseFileName, CommandLine], function=[count(), min(@timestamp, as=FirstSeen)])
| sort(FirstSeen, order=desc)
```

KQL

```
union
(DeviceProcessEvents | where Timestamp > ago(14d) and FileName in~ ("powershell.exe","pwsh.exe") | project Timestamp, DeviceName, AccountName, Parent = InitiatingProcessFileName, Text = ProcessCommandLine),
(DeviceEvents | where Timestamp > ago(14d) and ActionType == "PowerShellCommand" | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, Parent = InitiatingProcessParentFileName, Text = tostring(parse_json(AdditionalFields).Command))
| where Text matches regex @"(?i)(-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|-w(indowstyle)?\s+hid|\bIEX\b|Invoke-Expression|DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|FromBase64String|AmsiUtils|amsiInitFailed|Reflection\.Assembly\]::Load|Invoke-Mimikatz|-bxor)"
| extend Decoded = iff(Text matches regex @"(?i)-e(nc|ncodedcommand)?\s", base64_decode_tostring(extract(@"(?i)-e\w*\s+([A-Za-z0-9+/=]{20,})", 1, Text)), "")
| summarize Count = count(), FirstSeen = min(Timestamp), Hosts = make_set(DeviceName, 10) by AccountName, Parent, Text, Decoded
```

Elastic (ES|QL)

```
FROM logs-endpoint.events.process-*, logs-windows.powershell_operational-*
| WHERE (event.type == "start" AND TO_LOWER(process.name) IN ("powershell.exe","pwsh.exe")) OR event.code == "4104"
| EVAL text = COALESCE(process.command_line, powershell.file.script_block_text)
| WHERE text RLIKE """(?i).*(-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|-w(indowstyle)?\s+hid|IEX|Invoke-Expression|DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|FromBase64String|AmsiUtils|amsiInitFailed|Reflection\.Assembly\]::Load|Invoke-Mimikatz|-bxor).*"""
| STATS c = COUNT(*), first_seen = MIN(@timestamp), hosts = VALUES(host.name) BY user.name, process.parent.name, text
```

**Query 12B — WMI and Impacket-style remote execution**

Splunk

```
| tstats summariesonly=t count min(_time) as first_seen values(Processes.process) as cmds from datamodel=Endpoint.Processes
  where (Processes.parent_process_name="wmiprvse.exe" Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","mshta.exe"))
     OR (Processes.process_name="wmic.exe" Processes.process IN ("*/node:*","*process call create*"))
     OR (Processes.process_name="cmd.exe" Processes.process="*\\\\127.0.0.1\\ADMIN$\\*")
  by Processes.dest Processes.parent_process_name Processes.process_name Processes.user
| convert ctime(first_seen)
```

CrowdStrike

```
#event_simpleName=ProcessRollup2
| (ParentBaseFileName=/^wmiprvse\.exe$/i FileName=/^(cmd|powershell|pwsh|rundll32|mshta)\.exe$/i)
  OR (FileName=/^wmic\.exe$/i CommandLine=/\/node:|process\s+call\s+create/i)
  OR (FileName=/^cmd\.exe$/i CommandLine=/\\\\127\.0\.0\.1\\ADMIN\$\\/i)
| groupBy([ComputerName, ParentBaseFileName, FileName, CommandLine, UserName], function=[count(), min(@timestamp, as=FirstSeen)])
```

KQL

```
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (InitiatingProcessFileName =~ "wmiprvse.exe" and FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","mshta.exe"))
     or (FileName =~ "wmic.exe" and ProcessCommandLine matches regex @"(?i)/node:|process\s+call\s+create")
     or (FileName =~ "cmd.exe" and ProcessCommandLine has @"\\127.0.0.1\ADMIN$\")
| summarize Count = count(), FirstSeen = min(Timestamp), Cmds = make_set(ProcessCommandLine, 10) by DeviceName, InitiatingProcessFileName, FileName, AccountName
```

Elastic (ES|QL)

```
FROM logs-endpoint.events.process-*
| WHERE event.type == "start"
| WHERE (TO_LOWER(process.parent.name) == "wmiprvse.exe" AND TO_LOWER(process.name) IN ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","mshta.exe"))
   OR (TO_LOWER(process.name) == "wmic.exe" AND process.command_line RLIKE """(?i).*(/node:|process\s+call\s+create).*""")
   OR (TO_LOWER(process.name) == "cmd.exe" AND process.command_line LIKE "*127.0.0.1\\ADMIN$*")
| STATS c = COUNT(*), first_seen = MIN(@timestamp), cmds = VALUES(process.command_line) BY host.name, process.parent.name, process.name, user.name
```

**Common false positives:** SCCM/Intune scripts, monitoring agents using WMI, admin tooling that base64-encodes scripts. Allowlist by signed parent and service account.

---

[← Collection index](README.md) · [Repository home](../README.md)
