# H-02 — Windows persistence

**Hypothesis:** An intruder who gained execution on a Windows endpoint or server has created an autostart entry (registry ASEP, service, scheduled task, WMI subscription or startup-folder item) that launches a payload from a user-writable path or through a script/LOLBin interpreter.

**ATT&CK:** T1547.001 Registry Run Keys/Startup Folder, T1543.003 Windows Service, T1053.005 Scheduled Task, T1546.003 WMI Event Subscription, T1546.012 IFEO, T1546.015 COM Hijacking, T1547.004 Winlogon Helper, T1546.008 Accessibility Features, T1197 BITS Jobs.

**Data sources**

| Source | Events |
| --- | --- |
| Sysmon | EID 12/13/14 (registry), EID 11 (file create), EID 19/20/21 (WMI), EID 1 (process) |
| Windows Security / System | 4697 (service installed), 4698/4702 (task created/updated), 7045 (service installed, System log); requires "Audit Other Object Access" for tasks |
| CrowdStrike Falcon | `AsepValueUpdate`, `ScheduledTaskRegistered`, `ProcessRollup2`, `*Written` file events |
| Defender for Endpoint | `DeviceRegistryEvents`, `DeviceEvents` (ScheduledTaskCreated, ServiceInstalled, WmiBindEventFilterToConsumer), `DeviceFileEvents` |
| Elastic | `logs-endpoint.events.registry-*`, `logs-endpoint.events.file-*`, `logs-system.security-*`, `logs-windows.sysmon_operational-*` |

**Steps**

1. Run 2A over 30 days; stack by value data and keep entries present on 5 hosts or fewer.
2. Run 2B for new services and scheduled tasks whose command points to user-writable paths, encoded PowerShell or LOLBins.
3. Run 2C for WMI subscriptions and startup-folder drops; any WMI `CommandLineEventConsumer` or `ActiveScriptEventConsumer` outside known management tools is high-signal.
4. For each lead, identify the process that created the entry, its parent, the logon session and the user. Check whether the referenced file still exists and its hash prevalence.
5. Cross-check with Hunt 1 (side-loaded DLLs are often launched from a Run key or task).

**Query 2A — suspicious registry autostart entries (Run keys, Winlogon, IFEO, COM, services)**

Splunk

```
index=sysmon EventCode IN (12,13,14)
| regex TargetObject="(?i)(CurrentVersion\\(Run|RunOnce|Policies\\Explorer\\Run)|Winlogon\\(Userinit|Shell|Notify)|Image File Execution Options\\.+\\Debugger|SilentProcessExit|InprocServer32|AppInit_DLLs|Session Manager\\BootExecute|Services\\[^\\]+\\(ImagePath|Parameters\\ServiceDll))"
| regex Details="(?i)(\\Users\\|\\ProgramData\\|\\Temp\\|\\Public\\|powershell|cmd\.exe|mshta|rundll32|regsvr32|wscript|cscript|https?://)"
| stats count dc(host) as hosts values(host) as host_list values(Image) as writer by TargetObject Details
| where hosts<=5
```

CrowdStrike

```
#event_simpleName=AsepValueUpdate event_platform=Win
| RegObjectName=/(CurrentVersion\\(Run|RunOnce|Policies\\Explorer\\Run)|Winlogon|Image File Execution Options|SilentProcessExit|InprocServer32|AppInit_DLLs|BootExecute|\\Services\\)/i
| RegStringValue=/(\\Users\\|\\ProgramData\\|\\Temp\\|\\Public\\|powershell|cmd\.exe|mshta|rundll32|regsvr32|wscript|cscript|https?:\/\/)/i
| groupBy([RegObjectName, RegValueName, RegStringValue], function=[count(aid, distinct=true, as=Hosts), collect([ComputerName], limit=10)])
| Hosts <= 5
```

KQL

```
DeviceRegistryEvents
| where Timestamp > ago(30d) and ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey matches regex @"(?i)(CurrentVersion\\(Run|RunOnce|Policies\\Explorer\\Run)|Winlogon|Image File Execution Options|SilentProcessExit|InprocServer32|AppInit_DLLs|BootExecute|\\Services\\)"
| where RegistryValueData matches regex @"(?i)(\\Users\\|\\ProgramData\\|\\Temp\\|\\Public\\|powershell|cmd\.exe|mshta|rundll32|regsvr32|wscript|cscript|https?://)"
| summarize Hosts = dcount(DeviceId), HostList = make_set(DeviceName, 10), Writers = make_set(InitiatingProcessFileName, 5)
    by RegistryKey, RegistryValueName, RegistryValueData
| where Hosts <= 5
```

Elastic (ES|QL)

```
FROM logs-endpoint.events.registry-*
| WHERE host.os.type == "windows" AND event.action == "modification"
| WHERE TO_LOWER(registry.path) RLIKE """.*(currentversion\\(run|runonce|policies\\explorer\\run)|winlogon|image file execution options|silentprocessexit|inprocserver32|appinit_dlls|bootexecute|\\services\\).*"""
| EVAL data = TO_LOWER(MV_CONCAT(registry.data.strings, " "))
| WHERE data RLIKE """.*(\\users\\|\\programdata\\|\\temp\\|\\public\\|powershell|cmd\.exe|mshta|rundll32|regsvr32|wscript|cscript|https?://).*"""
| STATS hosts = COUNT_DISTINCT(host.name), writers = VALUES(process.name) BY registry.path, data
| WHERE hosts <= 5
```

**Query 2B — new services and scheduled tasks pointing at suspicious commands**

Splunk

```
(index=wineventlog source="WinEventLog:System" EventCode=7045) OR (index=wineventlog source="WinEventLog:Security" EventCode IN (4697,4698,4702))
| eval cmd=coalesce(Service_File_Name, ImagePath, Task_Content, TaskContent)
| regex cmd="(?i)(\\Users\\|\\ProgramData\\|\\Temp\\|\\Public\\|powershell|-enc|cmd\.exe\s+/c|mshta|rundll32|regsvr32|certutil|bitsadmin|https?://)"
| stats count min(_time) as first_seen by host EventCode Service_Name Task_Name cmd Subject_Account_Name
| convert ctime(first_seen)
```

CrowdStrike

```
(#event_simpleName=ScheduledTaskRegistered) OR (#event_simpleName=ProcessRollup2 FileName=/^(sc|schtasks)\.exe$/i CommandLine=/\s(create|\/create)\s/i)
| Cmd := concat([TaskExecCommand, " ", TaskExecArguments, CommandLine])
| Cmd=/(\\Users\\|\\ProgramData\\|\\Temp\\|\\Public\\|powershell|-enc|mshta|rundll32|regsvr32|certutil|bitsadmin|https?:\/\/)/i
| groupBy([ComputerName, UserName, TaskName, Cmd], function=[count(), min(@timestamp, as=FirstSeen)])
```

KQL (Defender tables + Windows events in Sentinel)

```
let sus = @"(?i)(\\Users\\|\\ProgramData\\|\\Temp\\|\\Public\\|powershell|-enc|cmd\.exe\s+/c|mshta|rundll32|regsvr32|certutil|bitsadmin|https?://)";
union
(DeviceEvents
 | where Timestamp > ago(30d) and ActionType in ("ScheduledTaskCreated","ScheduledTaskUpdated","ServiceInstalled")
 | extend Detail = tostring(AdditionalFields)
 | project Timestamp, DeviceName, ActionType, Detail, InitiatingProcessAccountName, InitiatingProcessCommandLine),
(SecurityEvent
 | where TimeGenerated > ago(30d) and EventID in (4697, 4698, 4702)
 | project Timestamp = TimeGenerated, DeviceName = Computer, ActionType = tostring(EventID), Detail = EventData, InitiatingProcessAccountName = SubjectUserName, InitiatingProcessCommandLine = ""),
(Event
 | where TimeGenerated > ago(30d) and EventLog == "System" and EventID == 7045
 | project Timestamp = TimeGenerated, DeviceName = Computer, ActionType = "7045", Detail = EventData, InitiatingProcessAccountName = UserName, InitiatingProcessCommandLine = "")
| where Detail matches regex sus
| order by Timestamp desc
```

Elastic (ES|QL)

```
FROM logs-system.security-*, logs-system.system-*
| WHERE event.code IN ("4697","4698","4702","7045")
| EVAL cmd = TO_LOWER(COALESCE(winlog.event_data.ImagePath, winlog.event_data.ServiceFileName, winlog.event_data.TaskContent))
| WHERE cmd RLIKE """.*(\\users\\|\\programdata\\|\\temp\\|\\public\\|powershell|-enc|mshta|rundll32|regsvr32|certutil|bitsadmin|https?://).*"""
| STATS c = COUNT(*), first_seen = MIN(@timestamp) BY host.name, event.code, winlog.event_data.ServiceName, winlog.event_data.TaskName, cmd
```

**Query 2C — WMI event subscriptions and startup-folder drops**

Splunk

```
index=sysmon (EventCode IN (19,20,21)) OR (EventCode=11 TargetFilename="*\\Start Menu\\Programs\\Startup\\*")
| eval artifact=coalesce(Destination, Consumer, Query, TargetFilename)
| stats count values(EventCode) as codes values(User) as users by host artifact Image
```

CrowdStrike

```
(#event_simpleName=ProcessRollup2 ParentBaseFileName=/^(scrcons|WmiPrvSE)\.exe$/i FileName=/^(powershell|pwsh|cmd|mshta|rundll32|regsvr32|wscript|cscript)\.exe$/i)
OR (#event_simpleName=/Written$/ TargetFileName=/\\Start Menu\\Programs\\Startup\\/i)
| groupBy([ComputerName, #event_simpleName, ParentBaseFileName, FileName, CommandLine, TargetFileName], function=count())
```

KQL

```
union
(DeviceEvents | where Timestamp > ago(30d) and ActionType == "WmiBindEventFilterToConsumer" | project Timestamp, DeviceName, ActionType, Detail = tostring(AdditionalFields)),
(DeviceFileEvents | where Timestamp > ago(30d) and FolderPath contains @"\Start Menu\Programs\Startup\" and ActionType == "FileCreated" | project Timestamp, DeviceName, ActionType, Detail = strcat(FolderPath, " by ", InitiatingProcessFileName)),
(DeviceProcessEvents | where Timestamp > ago(30d) and InitiatingProcessFileName =~ "scrcons.exe" | project Timestamp, DeviceName, ActionType, Detail = ProcessCommandLine)
```

Elastic (ES|QL)

```
FROM logs-endpoint.events.*
| WHERE (event.category == "file" AND event.type == "creation" AND TO_LOWER(file.path) LIKE "*\\start menu\\programs\\startup\\*")
   OR (event.category == "process" AND TO_LOWER(process.parent.name) IN ("scrcons.exe","wmiprvse.exe") AND TO_LOWER(process.name) IN ("powershell.exe","cmd.exe","mshta.exe","rundll32.exe","wscript.exe","cscript.exe"))
| STATS c = COUNT(*) BY host.name, process.parent.name, process.name, process.command_line, file.path
```

**Also check during this hunt:** `sethc.exe`/`utilman.exe` replaced or given an IFEO debugger; BITS jobs (`bitsadmin /SetNotifyCmdLine`); new Office add-ins under `%APPDATA%\Microsoft\Word\STARTUP`; netsh helper DLLs (`HKLM\SOFTWARE\Microsoft\NetSh`).

**Common false positives:** software updaters (Google, Adobe, Zoom), RMM/MDM agents, SCCM/Intune tasks, EDR self-protection keys. Baseline by writer process and signer.

---

[← Collection index](README.md) · [Repository home](../README.md)
