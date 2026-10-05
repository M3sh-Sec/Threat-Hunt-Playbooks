# H-01 — DLL side-loading (Windows)

**Hypothesis:** An adversary has placed a malicious DLL next to a legitimate, often signed, executable in a user-writable directory, so that the trusted binary loads attacker code and blends with normal process activity.

**ATT&CK:** T1574.002 DLL Side-Loading, T1574.001 DLL Search Order Hijacking, T1036.005 Masquerading. Long used by PlugX operators (Mustang Panda), APT41 and Lazarus, and by loaders delivered in ransomware intrusions.

**Data sources**

| Source | Event | Why |
| --- | --- | --- |
| Sysmon | EID 7 (Image Load), EID 11 (File Create), EID 1 (Process Create) | DLL path, signature status, hash, loading process |
| CrowdStrike Falcon | `ImageHash`, `ClassifiedModuleLoad`, `ProcessRollup2`, `NewExecutableWritten` / `PeFileWritten` | Module loads and new PE files written to disk |
| Defender for Endpoint | `DeviceImageLoadEvents`, `DeviceFileEvents`, `DeviceFileCertificateInfo` | Load events plus certificate data |
| Elastic Defend | `logs-endpoint.events.library-*`, `logs-endpoint.events.file-*` | `dll.path`, `dll.code_signature.*` |

Note: Sysmon EID 7 is very noisy; scope it to non-system paths in your Sysmon config. Falcon does not record every module load, so treat absence as inconclusive.

**Steps**

1. Run Query 1A to find unsigned or untrusted DLLs loaded from the same user-writable folder as the executable that loaded them.
2. Run Query 1B to find DLLs that carry Windows system names (for example `version.dll`, `dbghelp.dll`) but load from outside `System32`/`SysWOW64`/`WinSxS`.
3. Run Query 1C to find an EXE and DLL written to the same new folder within 5 minutes, a common delivery pattern (ZIP/ISO/MSI drop).
4. Stack results by DLL hash and keep those seen on 3 hosts or fewer.
5. For each lead: check the EXE's original filename vs. on-disk name, signer, child processes, outbound network connections, and whether the DLL exports only a few functions (proxy DLLs often forward the rest).
6. Pull the DLL for static analysis or sandboxing; search its hash across the fleet.

**Query 1A — unsigned DLL loaded from the executable's own user-writable folder**

Splunk

```
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7 (Signed=false OR SignatureStatus!=Valid)
| regex ImageLoaded="(?i)\\(Users|ProgramData|Windows\\Temp|AppData|Public|PerfLogs)\\"
| eval dll_dir=lower(replace(ImageLoaded,"\\[^\\]+$","")), proc_dir=lower(replace(Image,"\\[^\\]+$",""))
| where dll_dir=proc_dir
| stats count dc(host) as hosts values(host) as hosts_list min(_time) as first_seen max(_time) as last_seen by Image ImageLoaded Hashes Signature
| where hosts<=3
| convert ctime(first_seen) ctime(last_seen)
| sort first_seen desc
```

CrowdStrike (NG-SIEM / LogScale)

```
#event_simpleName=ImageHash event_platform=Win
| FileName=/\.dll$/i
| ImageFileName=/\\(Users|ProgramData|Windows\\Temp|AppData|Public|PerfLogs)\\/i
| join(query={#event_simpleName=ProcessRollup2 event_platform=Win | rename(field=ImageFileName, as=ProcImage)}, field=[aid, ContextProcessId], key=[aid, TargetProcessId], include=[ProcImage, CommandLine, ParentBaseFileName])
| replace(field=ImageFileName, regex="\\[^\\]+$", with="", as=DllDir)
| replace(field=ProcImage, regex="\\[^\\]+$", with="", as=ProcDir)
| DllDir := lower(DllDir) | ProcDir := lower(ProcDir)
| test(DllDir == ProcDir)
| groupBy([ProcImage, ImageFileName, SHA256HashData], function=[count(aid, distinct=true, as=Hosts), min(@timestamp, as=FirstSeen)])
| Hosts <= 3
```

Microsoft Sentinel / Defender (KQL)

```
let signed = DeviceFileCertificateInfo | where Timestamp > ago(30d) and IsSigned == 1 and IsTrusted == 1 | distinct SHA1;
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FolderPath matches regex @"(?i)\\(Users|ProgramData|Windows\\Temp|AppData|Public|PerfLogs)\\"
| where SHA1 !in (signed)
| extend DllDir = tolower(replace_regex(FolderPath, @"\\[^\\]+$", "")),
         ProcDir = tolower(replace_regex(InitiatingProcessFolderPath, @"\\[^\\]+\.exe$", ""))
| where DllDir == ProcDir
| summarize Hosts = dcount(DeviceId), HostList = make_set(DeviceName, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, FolderPath, SHA256
| where Hosts <= 3
| order by FirstSeen desc
```

Elastic (ES|QL)

```
FROM logs-endpoint.events.library-*
| WHERE host.os.type == "windows" AND event.action == "load"
| WHERE dll.code_signature.trusted == false OR dll.code_signature.exists == false
| WHERE TO_LOWER(dll.path) RLIKE """.*\\(users|programdata|windows\\temp|appdata|public|perflogs)\\.*"""
| EVAL dll_dir = TO_LOWER(REPLACE(dll.path, """\\[^\\]+$""", "")),
       proc_dir = TO_LOWER(REPLACE(process.executable, """\\[^\\]+$""", ""))
| WHERE dll_dir == proc_dir
| STATS hosts = COUNT_DISTINCT(host.name), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY process.executable, dll.path, dll.hash.sha256
| WHERE hosts <= 3
| SORT first_seen DESC
```

**Query 1B — Windows system DLL names loaded from non-system paths**

Commonly abused names: `version.dll, dbghelp.dll, dbgcore.dll, winmm.dll, wtsapi32.dll, cryptbase.dll, uxtheme.dll, dwrite.dll, msimg32.dll, userenv.dll, propsys.dll, secur32.dll, wininet.dll, mpsvc.dll, libcurl.dll, vcruntime140.dll, iphlpapi.dll`.

Splunk

```
index=sysmon EventCode=7
| eval dll=lower(mvindex(split(ImageLoaded,"\\"),-1))
| search dll IN ("version.dll","dbghelp.dll","dbgcore.dll","winmm.dll","wtsapi32.dll","cryptbase.dll","uxtheme.dll","dwrite.dll","msimg32.dll","userenv.dll","propsys.dll","secur32.dll","wininet.dll","mpsvc.dll","iphlpapi.dll")
| regex ImageLoaded!="(?i)^C:\\Windows\\(System32|SysWOW64|WinSxS)\\"
| stats count dc(host) as hosts values(Image) as loaders by ImageLoaded Hashes Signed
```

CrowdStrike

```
#event_simpleName=ImageHash event_platform=Win
| in(field=FileName, values=["version.dll","dbghelp.dll","dbgcore.dll","winmm.dll","wtsapi32.dll","cryptbase.dll","uxtheme.dll","dwrite.dll","msimg32.dll","userenv.dll","propsys.dll","secur32.dll","wininet.dll","mpsvc.dll","iphlpapi.dll"], ignoreCase=true)
| ImageFileName!=/\\Windows\\(System32|SysWOW64|WinSxS)\\/i
| groupBy([ImageFileName, SHA256HashData], function=count(aid, distinct=true, as=Hosts))
```

KQL

```
let names = dynamic(["version.dll","dbghelp.dll","dbgcore.dll","winmm.dll","wtsapi32.dll","cryptbase.dll","uxtheme.dll","dwrite.dll","msimg32.dll","userenv.dll","propsys.dll","secur32.dll","wininet.dll","mpsvc.dll","iphlpapi.dll"]);
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where tolower(FileName) in (names)
| where FolderPath !startswith @"C:\Windows\System32" and FolderPath !startswith @"C:\Windows\SysWOW64" and FolderPath !contains @"\WinSxS\"
| summarize Hosts = dcount(DeviceId), Loaders = make_set(InitiatingProcessFolderPath, 10) by FolderPath, SHA256
```

Elastic (ES|QL)

```
FROM logs-endpoint.events.library-*
| WHERE host.os.type == "windows" AND TO_LOWER(dll.name) IN ("version.dll","dbghelp.dll","dbgcore.dll","winmm.dll","wtsapi32.dll","cryptbase.dll","uxtheme.dll","dwrite.dll","msimg32.dll","userenv.dll","propsys.dll","secur32.dll","wininet.dll","mpsvc.dll","iphlpapi.dll")
| WHERE NOT TO_LOWER(dll.path) RLIKE """c:\\windows\\(system32|syswow64|winsxs)\\.*"""
| STATS hosts = COUNT_DISTINCT(host.name), loaders = VALUES(process.executable) BY dll.path, dll.hash.sha256
```

**Query 1C — EXE + DLL dropped together (Elastic EQL sequence; adapt as a transaction/join elsewhere)**

```
sequence by host.id with maxspan=5m
  [file where event.type == "creation" and file.extension == "exe" and file.path : ("C:\\Users\\*", "C:\\ProgramData\\*", "C:\\Windows\\Temp\\*")] by file.directory
  [file where event.type == "creation" and file.extension == "dll"] by file.directory
  [library where dll.code_signature.trusted != true] by dll.directory
```

Splunk equivalent: `index=sysmon EventCode=11 (TargetFilename="*.exe" OR TargetFilename="*.dll") | eval dir=replace(TargetFilename,"\\[^\\]+$","") | transaction host dir maxspan=5m | where eventcount>=2 AND like(TargetFilename,"%.exe%") AND like(TargetFilename,"%.dll%")`.

**Common false positives:** per-user installs (Teams, Zoom, Slack, OneDrive, Chrome updaters), portable dev tools, game launchers. Allowlist by signer + hash, never by path alone.

**Escalate when:** the EXE is signed by a major vendor but runs from `AppData`, `ProgramData` or `Public`; the DLL is unsigned and new to the fleet; or the process beacons to a rare external IP.

---

[← Collection index](README.md) · [Repository home](../README.md)
