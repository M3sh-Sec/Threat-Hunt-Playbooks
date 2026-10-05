# FS-02 — Business Email Compromise / Wire Fraud

**MITRE ATT&CK:** T1586, T1534

**Plain-English summary:** An attacker either compromises or convincingly impersonates an executive or advisor's email account and asks someone to move money or change payment/beneficiary details.

### Prerequisites
- Splunk access to `index=email` (content search — confirm legal/HR authorization since you're reading body text) and `index=policyadmin`.

### Step-by-Step
1. **Keyword search across subject/body.**
   ```spl
   index=email earliest=-7d
   | regex subject|body="(?i)(wire transfer|urgent|confidential|routing number|beneficiary change)"
   | table _time, sender, from_domain, display_name, recipient, subject
   ```
2. **Flag display-name-vs-domain mismatches.**
   ```spl
   index=email earliest=-7d
   | rex field=sender "@(?<from_domain>.+)$"
   | lookup legit_domains.csv domain AS from_domain OUTPUT domain AS is_legit
   | where isnull(is_legit)
   | table _time, display_name, sender, from_domain, subject
   ```
3. **Cross-reference flagged emails against account-change activity in the policy admin system.**
   ```spl
   index=policyadmin earliest=-7d change_type IN ("address","phone","email","beneficiary")
   | rename _time AS change_time
   | join account_id
     [ search index=email earliest=-7d
       | rex "(?i)(policy|account)[#:\s]*(?<account_id>[A-Z0-9\-]+)"
       | eval email_time=_time
       | table account_id, email_time, sender, subject ]
   | eval delta_hours=abs(change_time-email_time)/3600
   | where delta_hours<=72
   | table account_id, change_time, change_type, email_time, sender, subject, delta_hours
   ```
4. **Check timing/geography of the request.**
   ```spl
   index=policyadmin earliest=-7d
   | eval hour=strftime(_time,"%H")
   | where hour<7 OR hour>19
   | table _time, account_id, change_type, submitted_by_ip
   ```
5. **Verify before any money moves.** This step is manual/procedural, not SPL: notify the payments team to hold any transaction matching the pattern from Step 3 and verify out-of-band via a known-good phone number.

### If You Find Something
- **Any pending transaction matching the "change then request" pattern:** Escalate immediately — time-sensitive. Contact the fraud/payments team directly.
- **Completed transaction discovered after the fact:** Escalate to IR and fraud team same-day.

### Turn it into an alert
Save Step 3's query as an alert running every hour: "if number of results > 0" → notify fraud team distribution list directly (this one is urgent enough to bypass a queue).


---

[← Collection index](README.md) · [Repository home](../README.md)
