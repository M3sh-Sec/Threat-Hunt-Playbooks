# H-11 — Remote access software and tunnels (technique 8)

**Hypothesis:** An intruder has installed a commercial remote-management tool or tunneling utility that is not part of our approved stack, so they can come back interactively without malware and without our VPN.

**Data sources:** EDR process and network telemetry; DNS logs (Windows DNS, Infoblox, Umbrella, Zscaler); proxy logs; software inventory (SCCM/Intune). Scattered Spider has used many of these tools per [CISA AA23-320A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a).

**Steps**

1. Write down your approved remote-access tools (for example only ScreenConnect under your tenant ID). Everything else is a lead.
2. Run 11A for executions of RMM/tunnel binaries, including renamed copies (match on original filename or signer where available).
3. Run 11B for DNS/network connections to RMM and tunnel domains from hosts that should not use them.
4. For approved tools, check the instance/tenant ID in the command line or config (a ScreenConnect client pointing to a relay you don't own is malicious).
5. Check the install time against the user's sign-in history and help-desk tickets — RMM installs shortly after an MFA reset are a strong signal.

Tool list used below: `AnyDesk, ScreenConnect.ClientService / ConnectWiseControl, TeamViewer, Atera (AteraAgent), Splashtop (SRService, strwinclt), RustDesk, FleetDeck, Level, TacticalRMM, MeshAgent, NetSupport (client32), LogMeIn, Zoho Assist, RemotePC, Pulseway, SimpleHelp, ngrok, cloudflared, tailscale, chisel, plink`.

**Query 11A — RMM and tunnel binaries executed**

Splunk

```
| tstats summariesonly=t count min(_time) as first_seen values(Processes.process) as cmds values(Processes.dest) as hosts from datamodel=Endpoint.Processes
  where Processes.process_name IN ("anydesk.exe","screenconnect*.exe","connectwisecontrol*.exe","teamviewer*.exe","ateraagent.exe","srservice.exe","strwinclt.exe","rustdesk.exe","fleetdeck*.exe","level.exe","tacticalrmm.exe","meshagent.exe","client32.exe","logmein*.exe","zohoassist*.exe","remotepc*.exe","pulseway*.exe","simplehelp*.exe","ngrok.exe","cloudflared.exe","tailscale*.exe","chisel*.exe","plink.exe","ngrok","cloudflared","chisel")
  by Processes.process_name
| eval host_count=mvcount(hosts)
| convert ctime(first_seen)
| sort host_count
```

CrowdStrike

```
#event_simpleName=ProcessRollup2
| FileName=/^(anydesk|screenconnect.*|connectwisecontrol.*|teamviewer.*|ateraagent|srservice|strwinclt|rustdesk|fleetdeck.*|level|tacticalrmm|meshagent|client32|logmein.*|zohoassist.*|remotepc.*|pulseway.*|simplehelp.*|ngrok|cloudflared|tailscale.*|chisel.*|plink)(\.exe)?$/i
| groupBy([FileName], function=[count(aid, distinct=true, as=Hosts), min(@timestamp, as=FirstSeen), collect([ComputerName, CommandLine], limit=20)])
| sort(Hosts, order=asc)
```

KQL

```
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName matches regex @"(?i)^(anydesk|screenconnect.*|connectwisecontrol.*|teamviewer.*|ateraagent|srservice|strwinclt|rustdesk|fleetdeck.*|level|tacticalrmm|meshagent|client32|logmein.*|zohoassist.*|remotepc.*|pulseway.*|simplehelp.*|ngrok|cloudflared|tailscale.*|chisel.*|plink)(\.exe)?$"
   or ProcessVersionInfoOriginalFileName matches regex @"(?i)^(anydesk|teamviewer|rustdesk|ngrok|cloudflared|plink)"
| summarize Hosts = dcount(DeviceId), HostList = make_set(DeviceName, 20), FirstSeen = min(Timestamp), Cmds = make_set(ProcessCommandLine, 10) by FileName, ProcessVersionInfoCompanyName
| order by Hosts asc
```

Elastic (ES|QL)

```
FROM logs-endpoint.events.process-*
| WHERE event.type == "start"
| WHERE TO_LOWER(process.name) RLIKE """(anydesk|screenconnect.*|connectwisecontrol.*|teamviewer.*|ateraagent|srservice|strwinclt|rustdesk|fleetdeck.*|level|tacticalrmm|meshagent|client32|logmein.*|zohoassist.*|remotepc.*|pulseway.*|simplehelp.*|ngrok|cloudflared|tailscale.*|chisel.*|plink)(\.exe)?"""
   OR TO_LOWER(process.pe.original_file_name) RLIKE """(anydesk|teamviewer|rustdesk|ngrok|cloudflared|plink).*"""
| STATS hosts = COUNT_DISTINCT(host.name), host_list = VALUES(host.name), first_seen = MIN(@timestamp) BY process.name, process.code_signature.subject_name
| SORT hosts ASC
```

**Query 11B — DNS lookups to RMM and tunnel services**

Domains: `anydesk.com, net.anydesk.com, screenconnect.com, connectwise.com, teamviewer.com, atera.com, splashtop.com, rustdesk.com, fleetdeck.io, level.io, meshcentral.com, netsupportsoftware.com, logmein.com, zoho.com/assist, remotepc.com, pulseway.com, ngrok.io, ngrok-free.app, ngrok.app, trycloudflare.com, tailscale.com`.

Splunk: `| tstats summariesonly=t count values(DNS.src) as hosts from datamodel=Network_Resolution where DNS.query IN ("*anydesk.com","*screenconnect.com","*teamviewer.com","*atera.com","*splashtop.com","*rustdesk.com","*fleetdeck.io","*level.io","*netsupportsoftware.com","*logmein.com","*remotepc.com","*pulseway.com","*ngrok.io","*ngrok-free.app","*ngrok.app","*trycloudflare.com","*tailscale.com") by DNS.query | eval host_count=mvcount(hosts) | sort host_count`

CrowdStrike: `#event_simpleName=DnsRequest | DomainName=/(anydesk\.com|screenconnect\.com|teamviewer\.com|atera\.com|splashtop\.com|rustdesk\.com|fleetdeck\.io|level\.io|netsupportsoftware\.com|logmein\.com|remotepc\.com|pulseway\.com|ngrok\.io|ngrok-free\.app|ngrok\.app|trycloudflare\.com|tailscale\.com)$/i | groupBy([DomainName], function=[count(aid, distinct=true, as=Hosts), collect([ComputerName], limit=20)]) | sort(Hosts, order=asc)`

KQL: `DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteUrl matches regex @"(?i)(anydesk\.com|screenconnect\.com|teamviewer\.com|atera\.com|splashtop\.com|rustdesk\.com|fleetdeck\.io|level\.io|netsupportsoftware\.com|logmein\.com|remotepc\.com|pulseway\.com|ngrok\.io|ngrok-free\.app|ngrok\.app|trycloudflare\.com|tailscale\.com)$" | summarize Hosts = dcount(DeviceId), HostList = make_set(DeviceName, 20), Procs = make_set(InitiatingProcessFileName, 10) by RemoteUrl | order by Hosts asc`

Elastic ES|QL: `FROM logs-endpoint.events.network-* | WHERE dns.question.name RLIKE """.*(anydesk\.com|screenconnect\.com|teamviewer\.com|atera\.com|splashtop\.com|rustdesk\.com|fleetdeck\.io|level\.io|netsupportsoftware\.com|logmein\.com|remotepc\.com|pulseway\.com|ngrok\.io|ngrok-free\.app|ngrok\.app|trycloudflare\.com|tailscale\.com)""" | STATS hosts = COUNT_DISTINCT(host.name), host_list = VALUES(host.name), procs = VALUES(process.name) BY dns.question.name | SORT hosts ASC`

**Common false positives:** IT-approved tools, vendor support sessions, developers using ngrok. Rare tools on a handful of hosts are the priority.

---

[← Collection index](README.md) · [Repository home](../README.md)
