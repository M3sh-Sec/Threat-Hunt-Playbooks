# H-03 Linux persistence

**Hypothesis:** An adversary with access to a Linux server (often an internet-facing app server, jump host or Kubernetes node) has added a cron job, systemd unit, SSH key, shell-profile hook, preload library or local account so that access survives reboots and credential resets.

**ATT&CK:** T1053.003 Cron, T1543.002 Systemd Service, T1098.004 SSH Authorized Keys, T1546.004 Unix Shell Configuration Modification, T1574.006 Dynamic Linker Hijacking (`ld.so.preload`), T1136.001 Local Account, T1037.004 RC Scripts, T1556.003 PAM modification.

**Data sources**

| Source | What to collect |
| --- | --- |
| auditd (Splunk TA for Linux, Sentinel AMA/Syslog, Elastic Auditd Manager) | `-w` watch rules on `/etc/cron*`, `/var/spool/cron`, `/etc/systemd/system`, `/usr/lib/systemd/system`, `~/.config/systemd/user`, `/root/.ssh`, `/home/*/.ssh`, `/etc/ld.so.preload`, `/etc/profile`, `/etc/profile.d`, `/etc/bash.bashrc`, `~/.bashrc`, `/etc/rc.local`, `/etc/passwd`, `/etc/shadow`, `/etc/sudoers*`, `/etc/pam.d`, `/lib/security`; `execve` for `crontab`, `systemctl`, `useradd`, `usermod`, `chattr` |
| CrowdStrike Falcon (Linux) | `ProcessRollup2`, file-written events (`NewScriptWritten`, `*FileWritten`) |
| Defender for Endpoint (Linux) | `DeviceFileEvents`, `DeviceProcessEvents` |
| Elastic Defend (Linux) | `logs-endpoint.events.file-*`, `logs-endpoint.events.process-*` |

Recommended auditd keys used below: `persistence_cron`, `persistence_systemd`, `persistence_ssh`, `persistence_preload`, `persistence_shell`, `persistence_account`.

**Steps**

1. Confirm auditd or EDR file telemetry covers the paths above on a sample of hosts.
2. Run 3A for writes to persistence paths; exclude package managers (`dpkg`, `rpm`, `yum`, `dnf`, `apt`) and config management (`puppet`, `chef-client`, `ansible`, `salt-minion`).
3. Run 3B for persistence-creating commands, especially when the parent is a web server, database, Java process or an interactive SSH session from an unusual source.
4. On each lead, read the file content: look for reverse shells (`/dev/tcp`, `nc -e`, `bash -i`), `curl|wget ... | sh`, base64 blobs, and binaries in `/tmp`, `/dev/shm`, `/var/tmp`.
5. Diff `authorized_keys` against your key inventory; check `/etc/ld.so.preload` exists at all (it is normally absent).
6. For Kubernetes/OpenShift nodes, also review Hunt 7.

**Query 3A: writes to Linux persistence locations by non-package-manager processes**

Splunk (auditd)

```
index=linux sourcetype=linux:audit type=PATH
| regex name="^(/etc/cron|/var/spool/cron|/etc/systemd/system|/usr/lib/systemd/system|/lib/systemd/system|/root/\.ssh|/home/[^/]+/\.ssh|/etc/ld\.so\.preload|/etc/profile|/etc/bash\.bashrc|/root/\.bashrc|/home/[^/]+/\.(bashrc|profile|bash_profile)|/etc/rc\.local|/etc/sudoers|/etc/pam\.d|/lib/security|/etc/passwd)"
| join type=inner msg [search index=linux sourcetype=linux:audit type=SYSCALL | fields msg host comm exe auid uid ppid]
| search NOT comm IN (dpkg, rpm, yum, dnf, apt, apt-get, puppet, chef-client, ansible*, salt-minion, unattended-upgr*)
| stats count min(_time) as first_seen values(name) as files by host comm exe auid
| convert ctime(first_seen)
```

CrowdStrike

```
event_platform=Lin #event_simpleName=/Written$/
| TargetFileName=/^(\/etc\/cron|\/var\/spool\/cron|\/etc\/systemd\/system|\/usr\/lib\/systemd\/system|\/root\/\.ssh|\/home\/[^\/]+\/\.ssh|\/etc\/ld\.so\.preload|\/etc\/profile|\/etc\/bash\.bashrc|\/root\/\.bashrc|\/home\/[^\/]+\/\.(bashrc|profile)|\/etc\/rc\.local|\/etc\/sudoers|\/etc\/pam\.d|\/lib\/security)/
| join(query={event_platform=Lin #event_simpleName=ProcessRollup2}, field=[aid, ContextProcessId], key=[aid, TargetProcessId], include=[FileName, CommandLine, ParentBaseFileName, UserName])
| FileName!=/^(dpkg|rpm|yum|dnf|apt|apt-get|puppet|chef-client|salt-minion)$/
| groupBy([ComputerName, TargetFileName, FileName, ParentBaseFileName, UserName], function=[count(), min(@timestamp, as=FirstSeen)])
```

KQL (Defender for Endpoint on Linux)

```
DeviceFileEvents
| where Timestamp > ago(30d) and ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath matches regex @"^(/etc/cron|/var/spool/cron|/etc/systemd/system|/usr/lib/systemd/system|/root/\.ssh|/home/[^/]+/\.ssh|/etc/ld\.so\.preload|/etc/profile|/etc/bash\.bashrc|/root/\.bashrc|/home/[^/]+/\.(bashrc|profile)|/etc/rc\.local|/etc/sudoers|/etc/pam\.d|/lib/security)"
| where InitiatingProcessFileName !in~ ("dpkg","rpm","yum","dnf","apt","apt-get","puppet","chef-client","salt-minion")
| summarize Count = count(), FirstSeen = min(Timestamp), Files = make_set(FolderPath, 20)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```

KQL (Sentinel, auditd via Syslog)

```
Syslog
| where TimeGenerated > ago(30d) and (ProcessName == "audit" or SyslogMessage has "type=SYSCALL")
| where SyslogMessage has_any ("key=\"persistence_", "key=persistence_")
| extend Key = extract(@"key=\"?([\w_]+)", 1, SyslogMessage), Exe = extract(@"exe=\"([^\"]+)", 1, SyslogMessage), Auid = extract(@"auid=(\d+)", 1, SyslogMessage)
| where Exe !has_any ("dpkg","rpm","yum","dnf","apt","puppet","chef","salt")
| summarize Count = count(), FirstSeen = min(TimeGenerated) by Computer, Key, Exe, Auid
```

Elastic (ES|QL)

```
FROM logs-endpoint.events.file-*
| WHERE host.os.type == "linux" AND event.type IN ("creation","change")
| WHERE file.path RLIKE """(/etc/cron.*|/var/spool/cron.*|/etc/systemd/system.*|/usr/lib/systemd/system.*|/root/\.ssh.*|/home/[^/]+/\.ssh.*|/etc/ld\.so\.preload|/etc/profile.*|/etc/bash\.bashrc|/root/\.bashrc|/home/[^/]+/\.(bashrc|profile)|/etc/rc\.local|/etc/sudoers.*|/etc/pam\.d.*|/lib/security.*)"""
| WHERE NOT process.name IN ("dpkg","rpm","yum","dnf","apt","apt-get","puppet","chef-client","salt-minion")
| STATS c = COUNT(*), first_seen = MIN(@timestamp), files = VALUES(file.path) BY host.name, process.name, process.parent.name, user.name
```

**Query 3B: persistence-creating commands and suspicious parents**

Splunk

```
index=linux sourcetype=linux:audit type=EXECVE
| eval cmd=mvjoin(mvappend(a0,a1,a2,a3,a4,a5)," ")
| regex cmd="(crontab\s+(-e|-l|[^-])|systemctl\s+(enable|daemon-reload)|useradd|usermod\s+-aG\s+(sudo|wheel)|chattr\s+\+i|echo .*>>\s*\S*authorized_keys|/dev/tcp/|nc\s+-e|curl .*\|\s*(ba)?sh|wget .*\|\s*(ba)?sh)"
| stats count min(_time) as first_seen values(cmd) as cmds by host
```

CrowdStrike

```
event_platform=Lin #event_simpleName=ProcessRollup2
| CommandLine=/(crontab\s+(-e|[^-l])|systemctl\s+(enable|daemon-reload)|useradd|usermod\s+-aG\s+(sudo|wheel)|chattr\s+\+i|>>\s*\S*authorized_keys|\/dev\/tcp\/|nc\s+-e|curl .*\|\s*(ba)?sh|wget .*\|\s*(ba)?sh)/i
| groupBy([ComputerName, ParentBaseFileName, FileName, CommandLine, UserName], function=[count(), min(@timestamp, as=FirstSeen)])
| sort(FirstSeen, order=desc)
```

KQL

```
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine matches regex @"(crontab\s+(-e|[^-l])|systemctl\s+(enable|daemon-reload)|useradd|usermod\s+-aG\s+(sudo|wheel)|chattr\s+\+i|>>\s*\S*authorized_keys|/dev/tcp/|nc\s+-e|curl .*\|\s*(ba)?sh|wget .*\|\s*(ba)?sh)"
| extend SuspiciousParent = InitiatingProcessFileName in~ ("java","httpd","nginx","apache2","php-fpm","node","python3","tomcat","mysqld","postgres")
| summarize Count = count(), FirstSeen = min(Timestamp) by DeviceName, InitiatingProcessFileName, SuspiciousParent, ProcessCommandLine, AccountName
| order by SuspiciousParent desc, FirstSeen desc
```

Elastic (ES|QL)

```
FROM logs-endpoint.events.process-*
| WHERE host.os.type == "linux" AND event.type == "start"
| WHERE process.command_line RLIKE """.*(crontab\s+(-e|[^-l])|systemctl\s+(enable|daemon-reload)|useradd|usermod\s+-aG\s+(sudo|wheel)|chattr\s+\+i|>>\s*\S*authorized_keys|/dev/tcp/|nc\s+-e|curl .*\|\s*(ba)?sh|wget .*\|\s*(ba)?sh).*"""
| EVAL web_parent = process.parent.name IN ("java","httpd","nginx","apache2","php-fpm","node","tomcat","mysqld","postgres")
| STATS c = COUNT(*), first_seen = MIN(@timestamp) BY host.name, process.parent.name, web_parent, process.command_line, user.name
| SORT web_parent DESC, first_seen DESC
```

**Common false positives:** configuration-management runs, image-build pipelines (Packer), admins rotating keys. A write to `/etc/ld.so.preload` or a persistence command whose parent is a web or database process should always be escalated.

---

[← Collection index](README.md) · [Repository home](../README.md)
