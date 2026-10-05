# Threat landscape — who targets insurance, financial and distribution companies

The groups that matter most for companies like Allstate and UNFI are English-speaking, identity-focused extortion crews (Scattered Spider and the ShinyHunters/"Scattered Lapsus$ Hunters" cluster) and high-volume ransomware programs (Qilin, Akira, DragonForce, Cl0p). Their intrusions start with people and identity rather than malware, so most of the top 25 techniques below are identity, remote-access and living-off-the-land behaviors.

**Recent sector incidents**

| Date | Victim | What happened | Attribution |
| --- | --- | --- | --- |
| Jun 19, 2026 (data acquired) | Allstate | [Allstate notified state AGs in August 2026](https://www.claimdepot.com/data-breach/allstate-2026) that personal data including SSNs was taken; a ransomware group had [claimed the breach](https://www.insurancebusinessmag.com/us/news/cyber/allstate-breach-claim-raises-questions-about-scope-of-exposure-584600.aspx), with scope unconfirmed | Ransomware group claim; not formally attributed |
| Jun 2025 | Erie Insurance, Philadelphia Insurance, Aflac | Three insurers hit within five days; [Aflac said social engineering was used](https://cyberscoop.com/aflac-cyberattack-insurance-sector-scattered-spider/) | Hallmarks of Scattered Spider per Google GTIG |
| Jun 5, 2025 | UNFI | Systems taken offline across its distribution network; [up to $400M in lost sales](https://cyberscoop.com/united-natural-foods-cyberattack-400-million/) | Not officially attributed; [reporting links it to the Scattered Spider spree](https://securityboulevard.com/2025/06/united-natural-foods-hack-richixbw/) |
| Mid-2025 to early 2026 | Many Salesforce customers incl. insurers | Vishing + malicious connected apps; stolen Drift OAuth tokens | UNC6040 / UNC6395 (ShinyHunters cluster) |
| 2020–2021 | National General (Allstate subsidiary) | [Bots harvested driver's license numbers](https://ag.ny.gov/press-release/2025/attorney-general-james-sues-national-general-and-allstate-insurance-failing) from quote websites, \~199,000 people across two breaches | Unattributed automated attacks |

**Most active groups**

| Group (aliases) | Why it matters for this sector | Signature behaviors |
| --- | --- | --- |
| Scattered Spider (UNC3944, Octo Tempest, Muddled Libra) | [CrowdStrike saw it resume aggressive ransomware operations against insurers in 2025](https://www.crowdstrike.com/en-us/blog/crowdstrike-2026-financial-services-threat-landscape-report/); hit retail and distribution before pivoting to insurance | Help-desk vishing, MFA reset and push bombing, SIM swap, RMM tools, federated IdP added to Entra/Okta, NTDS theft, VM creation to evade EDR, DragonForce ransomware ([CISA AA23-320A, updated July 2025](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a)) |
| ShinyHunters / Scattered Lapsus$ Hunters (UNC6040, UNC6395) | SaaS data theft and extortion at scale, insurers among victims | Vishing to authorize rogue Salesforce apps, OAuth token abuse, Okta/M365 follow-on access, Mullvad VPN |
| Qilin, Akira, The Gentlemen | [Most prevalent extortion groups against financial services](https://www.intel471.com/blog/follow-the-money-the-financial-sectors-threat-landscape-in-2026), with insurance among the most impacted sub-sectors | VPN/edge exploitation, valid accounts, RMM, ESXi encryption, rclone exfil |
| DragonForce | Ransomware partner of Scattered Spider in 2025 | Encryption of VMware ESXi, data leak site |
| Cl0p | [Mass exploitation of shared enterprise platforms hit thousands of financial and insurance organizations](https://specopssoft.com/blog/top-threat-actors-targeting-insurance-industry/) | Zero-day exploitation of file-transfer and ERP apps, web shells, bulk exfil |
| MUTANT SPIDER, CHATTY SPIDER | [Vishing-led access sold to ransomware; data theft against financial firms](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-2026-financial-services-threat-landscape-report/) | Vishing, remote-support tools, quick exfil |
| DPRK-nexus (STARDUST CHOLLIMA / Lazarus, fake IT workers) | Theft of digital assets, insider placement at financial firms | Fake recruiter lures, malicious packages, DLL side-loading, legitimate remote tools |

**Top 25 techniques to hunt, mapped to hunts**

Selection is based on the CISA Scattered Spider advisory, the vendor sector reports linked above and common ransomware intrusion patterns. Hunt numbers point to the playbooks below and above.

| # | Technique | ATT&CK | Hunt |
| --- | --- | --- | --- |
| 1 | Vishing / help-desk social engineering | T1566.004 | 9 |
| 2 | Phishing links and adversary-in-the-middle credential/session theft | T1566.002, T1557 | 9 |
| 3 | MFA request generation (push bombing) | T1621 | 9 |
| 4 | Valid accounts — domain and cloud | T1078.002, T1078.004 | 9 |
| 5 | Attacker-registered MFA method or device | T1556.006, T1098.005 | 9 (and 5) |
| 6 | Exploit public-facing application | T1190 | 10 |
| 7 | External remote services (VPN, Citrix, RDP gateway) | T1133 | 10 |
| 8 | Remote access software (AnyDesk, ScreenConnect, TeamViewer, Atera, Splashtop) and tunnels (ngrok, Cloudflare Tunnel) | T1219, T1572 | 11 |
| 9 | PowerShell | T1059.001 | 12 |
| 10 | Windows command shell | T1059.003 | 12 |
| 11 | Windows Management Instrumentation | T1047 | 12 |
| 12 | Create account (AD and cloud) | T1136.002, T1136.003 | 13 |
| 13 | Domain/tenant trust modification (rogue federated IdP) | T1484.002 | 13 (and 5) |
| 14 | Steal or abuse application access tokens (OAuth/connected apps) | T1528, T1550.001 | 13 (and 8) |
| 15 | Scheduled task / service persistence | T1053.005, T1543.003 | 2 |
| 16 | Impair defenses (EDR tampering, BYOVD) | T1562.001 | 14 |
| 17 | Clear Windows event logs | T1070.001 | 14 |
| 18 | Create cloud VM to operate outside EDR coverage | T1578.002 | 14 |
| 19 | LSASS memory dumping | T1003.001 | 15 |
| 20 | NTDS.dit extraction (ntdsutil, VSS, DCSync) | T1003.003, T1003.006 | 15 |
| 21 | Credentials in files, vaults and wikis | T1552.001, T1555 | 15 |
| 22 | Active Directory and cloud discovery (AdFind, ADExplorer, BloodHound) | T1087.002, T1482 | 16 |
| 23 | Lateral movement over RDP, SMB/PsExec and WinRM | T1021.001, T1021.002, T1021.006 | 16 |
| 24 | Collection from SharePoint/Confluence and exfiltration to cloud storage (rclone, MEGA, S3) | T1213, T1567.002 | 17 |
| 25 | Data encrypted for impact and inhibit recovery (ESXi, vssadmin) | T1486, T1490 | 17 |

---

[← Collection index](README.md) · [Repository home](../README.md)
