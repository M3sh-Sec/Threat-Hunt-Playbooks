# Appendix — cadence, field mappings, porting notes, triage and sources

**Suggested cadence and priority**

Priority reflects what the most active groups against insurers and distributors do first; run P1 hunts weekly until each one is converted into a scheduled detection.

| Hunt | Priority | Cadence | Convert to detection? |
| --- | --- | --- | --- |
| 9 Identity takeover | P1 | Weekly | Yes — push bombing, reset → new-IP sign-in |
| 5 Azure/Entra persistence | P1 | Weekly | Yes — federation changes, app credentials, MFA added after reset |
| 8 Salesforce | P1 | Weekly | Yes — unknown connected app, bulk export |
| 11 RMM and tunnels | P1 | Weekly | Yes — unapproved tool execution |
| 13 Accounts and trust | P1 | Weekly | Yes — privileged group adds, new IdP |
| 15 Credential access | P1 | Weekly | Yes — DCSync, NTDS, LSASS |
| 17 Exfil and impact | P1 | Weekly | Yes — shadow deletion, rclone |
| 4 AWS, 6 GCP, 7 OpenShift | P2 | Bi-weekly | Yes for external trust, SA keys, cluster-admin bindings |
| 10 Exposed services | P2 | Bi-weekly, plus on every new KEV for your edge stack | Yes — web server spawning shells |
| 14 Defense evasion | P2 | Bi-weekly | Yes — tamper and log clearing |
| 1 DLL side-loading, 2 Windows persistence, 3 Linux persistence | P2 | Monthly | Partially — after allowlists mature |
| 12 Execution, 16 Discovery/lateral | P3 | Monthly | Partially — high-confidence patterns only |

**Cross-platform field mapping (endpoint)**

| Concept | Splunk (CIM / Sysmon) | CrowdStrike (Falcon) | KQL (Defender) | Elastic (ECS) |
| --- | --- | --- | --- | --- |
| Host | `dest` / `host` | `ComputerName`, `aid` | `DeviceName`, `DeviceId` | `host.name`, `host.id` |
| User | `user` / `User` | `UserName` | `AccountName` | `user.name` |
| Process path | `process_path` / `Image` | `ImageFileName` | `FolderPath` | `process.executable` |
| Process name | `process_name` | `FileName` | `FileName` | `process.name` |
| Command line | `process` / `CommandLine` | `CommandLine` | `ProcessCommandLine` | `process.command_line` |
| Parent name | `parent_process_name` / `ParentImage` | `ParentBaseFileName` | `InitiatingProcessFileName` | `process.parent.name` |
| File hash | `Hashes` | `SHA256HashData` | `SHA256` | `process.hash.sha256` / `dll.hash.sha256` |
| Loaded DLL | `ImageLoaded` (EID 7) | `ImageHash` / `ClassifiedModuleLoad` | `DeviceImageLoadEvents` | `dll.path` |
| Registry | `TargetObject`, `Details` (EID 13) | `AsepValueUpdate` → `RegObjectName`, `RegStringValue` | `RegistryKey`, `RegistryValueData` | `registry.path`, `registry.data.strings` |
| DNS | `Network_Resolution.query` | `DnsRequest` → `DomainName` | `DeviceNetworkEvents.RemoteUrl` | `dns.question.name` |

**Porting notes**

- **Splunk:** backslash escaping in `regex`/`rex` inside quotes can need doubling depending on context; test patterns with `| makeresults | eval x="C:\\Users\\a" | regex x="..."` first. Prefer `tstats` on accelerated data models for 30-day baselines.
- **CrowdStrike:** regex literals use `/.../i`; forward slashes inside need escaping as `\/`. `ImageHash` is not emitted for every module load, so treat DLL hunts as sampling. Third-party cloud and SaaS fields depend on the NG-SIEM parser; check with `#Vendor="aws" | head(5)` before running.
- **KQL:** use verbatim strings `@"..."` for paths and regex. `matches regex` is not anchored. Custom tables (`OCPAudit_CL`, `SalesforceServiceCloud_CL`, `OktaV2_CL`) depend on your connector version; confirm column names with `getschema`.
- **Elastic ES|QL:** `RLIKE` must match the whole string, so wrap patterns in `.*...*`. Use triple-quoted strings `"""..."""` to avoid double-escaping backslashes. Use EQL for ordered sequences (Queries 1C, 5A-2, 9B).

**Triage checklist for every lead**

1. Who: user/identity, whether it was recently reset or newly created, and its privilege tier.
2. Where from: source IP, ASN, country, device ID; compare with the identity's last 30 days.
3. What else: everything that identity and host did 24 hours before and after.
4. How it got there: parent process chain, sign-in method, ticket or change record.
5. Blast radius: other hosts or tenants with the same hash, IP, app ID or tool.
6. Outcome: benign (document and allowlist with signer/hash/identity, not path), suspicious (escalate with evidence), or detection candidate (write the rule, set severity, assign owner).

**Sources**

- [CISA AA23-320A — Scattered Spider (updated July 29, 2025)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a)
- [Google GTIG — The Cost of a Call: From Voice Phishing to Data Extortion (UNC6040)](https://cloud.google.com/blog/topics/threat-intelligence/voice-phishing-data-extortion)
- [Google GTIG — UNC6040 Proactive Hardening Recommendations](https://cloud.google.com/blog/topics/threat-intelligence/unc6040-proactive-hardening-recommendations)
- [Mitiga — ShinyHunters and UNC6395: Inside the Salesforce and Salesloft Breaches](https://www.mitiga.io/blog/shinyhunters-and-unc6395-inside-the-salesforce-and-salesloft-breaches)
- [CrowdStrike 2026 Financial Services Threat Landscape Report (blog)](https://www.crowdstrike.com/en-us/blog/crowdstrike-2026-financial-services-threat-landscape-report/) and [press release](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-2026-financial-services-threat-landscape-report/)
- [Intel 471 — Follow the Money: The Financial Sector's Threat Landscape in 2026](https://www.intel471.com/blog/follow-the-money-the-financial-sectors-threat-landscape-in-2026)
- [Specops — Top 3 Threat Actors Targeting the Insurance Industry in 2026](https://specopssoft.com/blog/top-threat-actors-targeting-insurance-industry/)
- [CyberScoop — Aflac duped by social-engineering attack](https://cyberscoop.com/aflac-cyberattack-insurance-sector-scattered-spider/)
- [CyberScoop — United Natural Foods loses up to $400M in sales after cyberattack](https://cyberscoop.com/united-natural-foods-cyberattack-400-million/)
- [Security Boulevard — UNFI hack and Scattered Spider](https://securityboulevard.com/2025/06/united-natural-foods-hack-richixbw/)
- [Insurance Business — Allstate breach claim](https://www.insurancebusinessmag.com/us/news/cyber/allstate-breach-claim-raises-questions-about-scope-of-exposure-584600.aspx)
- [ClaimDepot — Allstate data breach notice summary (2026)](https://www.claimdepot.com/data-breach/allstate-2026)
- [New York Attorney General — National General and Allstate lawsuit](https://ag.ny.gov/press-release/2025/attorney-general-james-sues-national-general-and-allstate-insurance-failing)
- [LOLDrivers — vulnerable driver list](https://www.loldrivers.io/)

---

[← Collection index](README.md) · [Repository home](../README.md)
