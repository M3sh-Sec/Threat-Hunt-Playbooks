# Threat Hunting Playbooks: Financial Services & Insurance

Two complementary collections of threat hunts for insurance, wealth-management, financial-services and distribution companies, packaged together:

| Collection | What it covers | Platforms | Audience |
|---|---|---|---|
| [**Splunk fraud & business-process playbooks**](splunk-fraud-playbooks/README.md) (FS-00 to FS-15) | BEC and wire fraud, call-center vishing, SIM swap, credential stuffing, insider misuse, vendor access, customer-portal and API abuse, executive targeting | Splunk (SPL) | First-time hunters, with every step spelled out |
| [**Multi-platform hunts**](multi-platform-hunts/README.md) (H-00 to H-17) | DLL side-loading; persistence on Windows, Linux, AWS, Azure/Entra, GCP, OpenShift and Salesforce; the top 25 techniques of Scattered Spider, ShinyHunters and ransomware crews targeting the sector | Splunk, CrowdStrike Falcon / NG-SIEM, Microsoft Sentinel / Defender, Elastic | Experienced hunters |

> **Before running anything:** index, sourcetype, table and field names are illustrative. Map them to your environment first. See [FS-00](splunk-fraud-playbooks/FS-00-before-you-start-splunk-basics-and-ground-rules.md) for Splunk and the [appendix](multi-platform-hunts/appendix-cadence-field-mappings-sources.md) for the other platforms.

## Where the collections overlap

Use the FS playbook for the business-process angle (policy-admin, call-center and payment data) and the H hunt for endpoint, identity-provider and cloud telemetry.

| Theme | Splunk fraud playbook | Related FS playbook | Multi-platform hunts |
|---|---|---|---|
| Phishing, vishing and identity takeover | [FS-01 Spearphishing](splunk-fraud-playbooks/FS-01-spearphishing-for-credential-theft.md) | [FS-09 Call-center vishing](splunk-fraud-playbooks/FS-09-vishing-call-center-social-engineering.md) | [H-09 Identity takeover](multi-platform-hunts/H-09-identity-takeover-vishing-mfa-fatigue-aitm-and-rogue-mfa-devices.md) |
| Credential stuffing / valid accounts | [FS-03 Credential stuffing](splunk-fraud-playbooks/FS-03-valid-account-abuse-credential-stuffing.md) |  | [H-09 Identity takeover](multi-platform-hunts/H-09-identity-takeover-vishing-mfa-fatigue-aitm-and-rogue-mfa-devices.md) |
| OAuth / app-consent abuse | [FS-04 OAuth token abuse](splunk-fraud-playbooks/FS-04-cloud-identity-oauth-token-abuse.md) |  | [H-05 Azure/Entra](multi-platform-hunts/H-05-azure-and-entra-id-persistence.md), [H-08 Salesforce](multi-platform-hunts/H-08-salesforce-persistence-and-data-theft.md), [H-13 Accounts and trust](multi-platform-hunts/H-13-account-and-trust-persistence-new-accounts-privileged-groups-rogue-idps-and.md) |
| MFA bypass | [FS-10 SIM swap](splunk-fraud-playbooks/FS-10-sim-swap-enabled-mfa-bypass.md) |  | [H-09 Identity takeover](multi-platform-hunts/H-09-identity-takeover-vishing-mfa-fatigue-aitm-and-rogue-mfa-devices.md) |
| Customer portal / exposed apps | [FS-08 Web app attacks](splunk-fraud-playbooks/FS-08-web-application-attacks-against-customer-portals.md) | [FS-14 API abuse](splunk-fraud-playbooks/FS-14-api-abuse-for-automated-account-enumerationtakeover.md) | [H-10 Exposed services](multi-platform-hunts/H-10-exploited-public-facing-apps-and-external-remote-services.md) |
| Remote access tools | [FS-05 Ransomware precursors (step 3)](splunk-fraud-playbooks/FS-05-ransomware-precursor-activity.md) |  | [H-11 RMM and tunnels](multi-platform-hunts/H-11-remote-access-software-and-tunnels.md) |
| Lateral movement | [FS-11 RDP/SMB](splunk-fraud-playbooks/FS-11-lateral-movement-via-rdpsmb.md) |  | [H-16 Discovery and lateral](multi-platform-hunts/H-16-discovery-and-lateral-movement.md) |
| Exfiltration | [FS-12 Cloud storage exfil](splunk-fraud-playbooks/FS-12-data-exfiltration-via-cloud-storage-personal-accounts.md) | [FS-07 Insider misuse](splunk-fraud-playbooks/FS-07-insider-threat-privileged-misuse.md) | [H-17 Exfil and impact](multi-platform-hunts/H-17-collection-exfiltration-and-ransomware-precursors.md) |
| Ransomware precursors | [FS-05 Ransomware precursors](splunk-fraud-playbooks/FS-05-ransomware-precursor-activity.md) |  | [H-14 Defense evasion](multi-platform-hunts/H-14-defense-evasion-edr-tampering-log-clearing-and-rogue-cloud-vms.md), [H-17 Exfil and impact](multi-platform-hunts/H-17-collection-exfiltration-and-ransomware-precursors.md) |

Hunts with no counterpart: FS-02 (BEC/wire fraud), FS-06 (vendor supply chain), FS-13 (malicious macros), FS-15 (executive/HNW targeting); H-01 to H-04, H-06, H-07 (side-loading and cross-platform persistence), H-12 (LOLBin execution) and H-15 (credential access).

## Repository structure

```
.
├── README.md                     ← you are here
├── GENERAL-NOTES.md              ← cadence and program guidance for both collections
├── splunk-fraud-playbooks/       ← FS-00 … FS-15, one file per playbook
├── multi-platform-hunts/         ← H-00 … H-17, threat landscape, appendix
├── templates/
│   ├── documentation-template.md ← fill in for every hunt
│   └── lookups/                  ← empty CSV headers for the lookups the hunts reference
├── .gitignore                    ← keeps populated lookup data out of Git
└── LICENSE                       ← MIT
```

## Getting started

1. Read [FS-00](splunk-fraud-playbooks/FS-00-before-you-start-splunk-basics-and-ground-rules.md) (Splunk basics and ground rules) and [H-00](multi-platform-hunts/H-00-how-to-use.md) (hunt loop and query conventions).
2. Copy `templates/lookups/` to `lookups/`, populate the files you need, and upload them to your SIEM. The `lookups/` folder is git-ignored so real data is never committed.
3. Pick hunts by priority: the weekly P1 set is listed in the [appendix cadence table](multi-platform-hunts/appendix-cadence-field-mappings-sources.md); for the FS series start with FS-01, FS-03, FS-05 and FS-09.
4. Record every run with the [documentation template](templates/documentation-template.md) and convert validated hunts into scheduled detections.

Threat intelligence in the multi-platform collection is current as of October 5, 2026; sources are listed in the appendix.
