# Splunk Fraud & Business-Process Playbooks (FS-00 to FS-15)

Step-by-step Splunk hunts for the fraud and business-application tactics that hit financial services and insurance firms: BEC and wire fraud, call-center vishing, SIM swap, insider misuse, customer-portal and API abuse. Written so a first-time hunter can run them.

### Splunk Edition (SPL queries, written for a first-time threat hunter)

**Scope:** large insurance/wealth-management/financial-services firms: agent/advisor networks, policyholder PII, wire/withdrawal capability, high-net-worth clients, regulated environment.

**Assumed environment for these examples:** Splunk Enterprise/Cloud with Enterprise Security (ES) or at minimum the Common Information Model (CIM) apps installed. Index and sourcetype names below are **illustrative**. Swap them for whatever your actual Splunk admin has configured (check `| eventcount summarize=false index=*` or ask your Splunk admin for the real index names if you're not sure).

---

| ID | Playbook | MITRE ATT&CK |
|---|---|---|
| FS-00 | [Before You Start: Splunk Basics & Ground Rules](FS-00-before-you-start-splunk-basics-and-ground-rules.md) | - |
| FS-01 | [Spearphishing for Credential Theft](FS-01-spearphishing-for-credential-theft.md) | T1566.001, T1566.002 |
| FS-02 | [Business Email Compromise / Wire Fraud](FS-02-business-email-compromise-wire-fraud.md) | T1586, T1534 |
| FS-03 | [Valid Account Abuse / Credential Stuffing](FS-03-valid-account-abuse-credential-stuffing.md) | T1078, T1110.004 |
| FS-04 | [Cloud Identity / OAuth Token Abuse](FS-04-cloud-identity-oauth-token-abuse.md) | T1550.001, T1528 |
| FS-05 | [Ransomware Precursor Activity](FS-05-ransomware-precursor-activity.md) | T1486, T1490, TA0040 |
| FS-06 | [Third-Party / Vendor Supply Chain Compromise](FS-06-third-party-vendor-supply-chain-compromise.md) | T1195 |
| FS-07 | [Insider Threat / Privileged Misuse](FS-07-insider-threat-privileged-misuse.md) | T1078.002 |
| FS-08 | [Web Application Attacks Against Customer Portals](FS-08-web-application-attacks-against-customer-portals.md) | T1190 |
| FS-09 | [Vishing / Call-Center Social Engineering](FS-09-vishing-call-center-social-engineering.md) | T1598, T1656 |
| FS-10 | [SIM Swap Enabled MFA Bypass](FS-10-sim-swap-enabled-mfa-bypass.md) | T1621, T1451 |
| FS-11 | [Lateral Movement via RDP/SMB](FS-11-lateral-movement-via-rdpsmb.md) | T1021.001, T1021.002 |
| FS-12 | [Data Exfiltration via Cloud Storage / Personal Accounts](FS-12-data-exfiltration-via-cloud-storage-personal-accounts.md) | T1567 |
| FS-13 | [Malicious Macro / HTA Delivery via Document Attachments](FS-13-malicious-macro-hta-delivery-via-document-attachments.md) | T1204.002, T1566.001 |
| FS-14 | [API Abuse for Automated Account Enumeration/Takeover](FS-14-api-abuse-for-automated-account-enumerationtakeover.md) | - |
| FS-15 | [Executive/HNW Client Targeting & Reconnaissance](FS-15-executivehnw-client-targeting-and-reconnaissance.md) | T1591, T1598.003 |

See also the [hunt documentation template](../templates/documentation-template.md) and [program notes](../GENERAL-NOTES.md).
