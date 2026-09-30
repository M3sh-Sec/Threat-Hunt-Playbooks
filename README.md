# Threat Hunting Playbooks — Financial Services & Insurance Sector (Splunk Edition)

A set of 15 step-by-step threat hunting playbooks tailored to the tactics most commonly used against large insurance / wealth-management / financial-services firms, agent and advisor networks, policyholder PII, wire and withdrawal capability, high-net-worth clients, and regulated environments.

Every playbook includes plain-English context, prerequisites, numbered steps with real **Splunk SPL** queries, "what normal vs. suspicious looks like" guidance, and clear escalation criteria. Written so a first-time threat hunter can pick a playbook and run it.

> **Before running anything:** index, sourcetype, and field names throughout these playbooks are illustrative placeholders (e.g. `index=email`, `sourcetype=proofpoint`). Adjust them to match your actual Splunk environment — see [`playbooks/00-before-you-start-splunk-basics-ground-rules.md`](playbooks/00-before-you-start-splunk-basics-ground-rules.md) for how to confirm real index/sourcetype names, plus SPL basics and ground rules that apply to every hunt.

## Contents

| # | Playbook | MITRE ATT&CK |
|---|---|---|
| 0 | [Before You Start: Splunk Basics & Ground Rules](playbooks/00-before-you-start-splunk-basics-ground-rules.md) | — |
| 1 | [Spearphishing for Credential Theft](playbooks/01-spearphishing-for-credential-theft-t1566001-t1566002.md) | T1566.001, T1566.002 |
| 2 | [Business Email Compromise / Wire Fraud](playbooks/02-business-email-compromise-wire-fraud-t1586-t1534.md) | T1586, T1534 |
| 3 | [Valid Account Abuse / Credential Stuffing](playbooks/03-valid-account-abuse-credential-stuffing-t1078-t1110004.md) | T1078, T1110.004 |
| 4 | [Cloud Identity / OAuth Token Abuse](playbooks/04-cloud-identity-oauth-token-abuse-t1550001-t1528.md) | T1550.001, T1528 |
| 5 | [Ransomware Precursor Activity](playbooks/05-ransomware-precursor-activity-t1486-t1490-ta0040.md) | T1486, T1490, TA0040 |
| 6 | [Third-Party / Vendor Supply Chain Compromise](playbooks/06-third-party-vendor-supply-chain-compromise-t1195.md) | T1195 |
| 7 | [Insider Threat / Privileged Misuse](playbooks/07-insider-threat-privileged-misuse-t1078002.md) | T1078.002 |
| 8 | [Web Application Attacks Against Customer Portals](playbooks/08-web-application-attacks-against-customer-portals-t1190.md) | T1190 |
| 9 | [Vishing / Call-Center Social Engineering](playbooks/09-vishing-call-center-social-engineering-t1598-t1656.md) | T1598, T1656 |
| 10 | [SIM Swap Enabled MFA Bypass](playbooks/10-sim-swap-enabled-mfa-bypass-t1621-t1451.md) | T1621, T1451 |
| 11 | [Lateral Movement via RDP/SMB](playbooks/11-lateral-movement-via-rdpsmb-t1021001-t1021002.md) | T1021.001, T1021.002 |
| 12 | [Data Exfiltration via Cloud Storage / Personal Accounts](playbooks/12-data-exfiltration-via-cloud-storage-personal-accounts-t1567.md) | T1567 |
| 13 | [Malicious Macro / HTA Delivery via Document Attachments](playbooks/13-malicious-macro-hta-delivery-via-document-attachments-t1204002-t1566001.md) | T1204.002, T1566.001 |
| 14 | [API Abuse for Automated Account Enumeration/Takeover](playbooks/14-api-abuse-for-automated-account-enumerationtakeover.md) | — |
| 15 | [Executive/HNW Client Targeting & Reconnaissance](playbooks/15-executivehnw-client-targeting-reconnaissance-t1591-t1598003.md) | T1591, T1598.003 |

See also: [General Program Notes](GENERAL-NOTES.md) and the [Hunt Documentation Template](templates/documentation-template.md).

## Repository structure

```
.
├── README.md                          # this file
├── GENERAL-NOTES.md                   # program-level guidance (cadence, prioritization, ES notes)
├── playbooks/                         # one file per playbook
│   ├── 00-before-you-start-splunk-basics-ground-rules.md
│   ├── 01-spearphishing-for-credential-theft-t1566001-t1566002.md
│   ├── ...
│   └── 15-executivehnw-client-targeting-reconnaissance-t1591-t1598003.md
└── templates/
    ├── documentation-template.md      # copy this for every hunt you run
    └── lookups/                       # starter CSV templates referenced by the SPL queries
        ├── legit_domains.csv
        ├── lookalike_domains.csv
        ├── vendor_access_inventory.csv
        ├── approved_jump_hosts.csv
        ├── approved_software.csv
        ├── hr_departures.csv
        ├── vip_policy_accounts.csv
        ├── verified_publishers.csv
        ├── partner_integration_profile.csv
        └── executive_watchlist.csv
```

## Getting started

1. Read [`playbooks/00-before-you-start-splunk-basics-ground-rules.md`](playbooks/00-before-you-start-splunk-basics-ground-rules.md) first — it covers SPL basics, ground rules, and the index/sourcetype naming assumptions used throughout.
2. Upload the CSV files in `templates/lookups/` into Splunk as lookup table files (Settings > Lookups > Lookup table files) and populate them with your organization's real data before running queries that reference them.
3. Start with Playbooks 1, 3, 5, and 9 — they have the clearest signals and are the most common attack paths against this sector.
4. Use [`templates/documentation-template.md`](templates/documentation-template.md) to log every hunt you run.
5. Once a hunt is validated (low false-positive rate), save it as a Splunk **Alert** per the "Turn it into an alert" note at the end of each playbook.

## Contributing

These playbooks are meant to evolve. If you tune a query for your environment, add a detection, or find a false-positive pattern worth documenting, consider opening a pull request so the team benefits. Suggested additions: real index/sourcetype mappings for your environment (as a separate, internal-only config reference — do not commit real production index names, internal hostnames, or actual customer/vendor data to a public repo), new playbooks for emerging tactics, and dashboards built from the saved searches.

## Disclaimer

These playbooks are generic starting points based on publicly known attacker tactics common to the financial services and insurance sector. They are not based on any specific company's actual environment, infrastructure, or incident history. Field names, index names, and thresholds must be validated and tuned against your own environment before operational use.
