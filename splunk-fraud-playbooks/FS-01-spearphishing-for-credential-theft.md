# FS-01 — Spearphishing for Credential Theft

**MITRE ATT&CK:** T1566.001, T1566.002

**Plain-English summary:** Attackers send fake emails (pretending to be IT, DocuSign, or an internal portal) to trick an advisor or employee into typing their password into a fake login page.

### Prerequisites
- Splunk access to `index=email` and `index=identity`.
- A lookup file of your organization's legitimate domains (create one: Settings > Lookups > Lookup table files, name it `legit_domains.csv` with one column `domain`).

### Step-by-Step
1. **Generate look-alike domains outside Splunk, then bring the list in.**
   - Run `dnstwist yourcompany.com` on a separate machine, export the results to a CSV, and upload it as a Splunk lookup table (Settings > Lookups > Add new > Lookup table files) named `lookalike_domains.csv` with a column `domain`.
2. **Search email logs for mail from look-alike domains.**
   ```spl
   index=email earliest=-7d
   | rex field=sender "@(?<sender_domain>.+)$"
   | lookup lookalike_domains.csv domain AS sender_domain OUTPUT domain AS matched
   | where isnotnull(matched)
   | table _time, sender, recipient, subject
   ```
3. **Pull URL-click / "URL defense" events and filter for low-reputation or newly-registered links.**
   ```spl
   index=email sourcetype=proofpoint action=click earliest=-7d
   | where url_reputation="unknown" OR domain_age_days<30
   | table _time, user, url, url_reputation, domain_age_days
   ```
   *(Field names like `url_reputation` and `domain_age_days` depend on your email security add-on — check `| fieldsummary` on the raw sourcetype if these don't match.)*
4. **Check for a sign-in shortly after each suspicious click (join in SPL using `transaction` or a subsearch).**
   ```spl
   index=email sourcetype=proofpoint action=click earliest=-7d
   [ search index=email sourcetype=proofpoint action=click earliest=-7d
     | table user, _time
     | rename _time AS click_time ]
   | join user
     [ search index=identity earliest=-7d
       | eval signin_time=_time
       | table user, signin_time, src_ip, city, country ]
   | eval delta_minutes=abs(signin_time-click_time)/60
   | where delta_minutes<=15
   | table user, click_time, signin_time, src_ip, city, country, delta_minutes
   ```
   *Simpler alternative if `join` performs poorly in your environment: run the click search and sign-in search separately, export both to CSV, and manually cross-reference by username/timestamp for your first few hunts.*
5. **Check for new mailbox rules or OAuth grants created right after** (see Playbook 4, Step 1 for the exact query — reuse it, filtered to the users flagged above).
6. **Score and shortlist.**
   ```spl
   | eval risk_score=case(delta_minutes<=15 AND matched_lookalike=1, 3, matched_lookalike=1, 1, 1=1, 0)
   | where risk_score>=1
   | sort -risk_score
   ```

### If You Find Something
- **High priority (click + new-location sign-in within 15 min):** Escalate to IR immediately with the `table` output above attached. Recommend password reset and session revocation (IR/IT will execute).
- **Medium (click only, no follow-on sign-in anomaly):** Save the domain to `lookalike_domains.csv` for future hunts, no further action for 7 days.

### Turn it into an alert
Save Step 4's query as a Splunk **Alert**: trigger "if number of results > 0", run every 4 hours, send email/Slack to your SOC channel.


---

[← Collection index](README.md) · [Repository home](../README.md)
