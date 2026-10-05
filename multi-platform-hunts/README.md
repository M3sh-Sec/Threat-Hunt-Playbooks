# Multi-Platform Threat Hunts (H-01 to H-17)

Hypothesis-driven hunts with queries for **Splunk (SPL), CrowdStrike Falcon (CQL / NG-SIEM), Microsoft Sentinel / Defender (KQL) and Elastic (ES|QL / EQL)**. H-01 to H-08 cover DLL side-loading and persistence across Windows, Linux, AWS, Azure/Entra, GCP, OpenShift and Salesforce. H-09 to H-17 cover the top 25 techniques used by the groups most active against insurance, financial services and distribution companies.

Start with [H-00: How to use these hunts](H-00-how-to-use.md) and the [threat landscape](threat-landscape-and-top-25-techniques.md).

| ID | Hunt |
|---|---|
| H-01 | [DLL side-loading (Windows)](H-01-dll-side-loading-windows.md) |
| H-02 | [Windows persistence](H-02-windows-persistence.md) |
| H-03 | [Linux persistence](H-03-linux-persistence.md) |
| H-04 | [AWS persistence](H-04-aws-persistence.md) |
| H-05 | [Azure and Entra ID persistence](H-05-azure-and-entra-id-persistence.md) |
| H-06 | [GCP persistence](H-06-gcp-persistence.md) |
| H-07 | [OpenShift (OCP) persistence](H-07-openshift-ocp-persistence.md) |
| H-08 | [Salesforce persistence and data theft](H-08-salesforce-persistence-and-data-theft.md) |
| H-09 | [Identity takeover: vishing, MFA fatigue, AiTM and rogue MFA devices (techniques 1-5)](H-09-identity-takeover-vishing-mfa-fatigue-aitm-and-rogue-mfa-devices.md) |
| H-10 | [Exploited public-facing apps and external remote services (techniques 6-7)](H-10-exploited-public-facing-apps-and-external-remote-services.md) |
| H-11 | [Remote access software and tunnels (technique 8)](H-11-remote-access-software-and-tunnels.md) |
| H-12 | [Living-off-the-land execution: PowerShell, cmd and WMI (techniques 9-11)](H-12-living-off-the-land-execution-powershell-cmd-and-wmi.md) |
| H-13 | [Account and trust persistence: new accounts, privileged groups, rogue IdPs and OAuth grants (techniques 12-14)](H-13-account-and-trust-persistence-new-accounts-privileged-groups-rogue-idps-and.md) |
| H-14 | [Defense evasion: EDR tampering, log clearing and rogue cloud VMs (techniques 16-18)](H-14-defense-evasion-edr-tampering-log-clearing-and-rogue-cloud-vms.md) |
| H-15 | [Credential access: LSASS, NTDS.dit and credential stores (techniques 19-21)](H-15-credential-access-lsass-ntdsdit-and-credential-stores.md) |
| H-16 | [Discovery and lateral movement (techniques 22-23)](H-16-discovery-and-lateral-movement.md) |
| H-17 | [Collection, exfiltration and ransomware precursors (techniques 24-25)](H-17-collection-exfiltration-and-ransomware-precursors.md) |

Reference: [Appendix: cadence, field mappings, porting notes, triage and sources](appendix-cadence-field-mappings-sources.md)
