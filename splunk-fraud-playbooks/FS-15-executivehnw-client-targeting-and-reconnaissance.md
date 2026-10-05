# FS-15 Executive/HNW Client Targeting & Reconnaissance

**MITRE ATT&CK:** T1591, T1598.003

**Plain-English summary:** Attackers research specific executives/advisors/high-net-worth clients before a highly targeted attack.

### Prerequisites
- Splunk access to `index=email` and a lookup `executive_watchlist.csv` (columns: `email`, `name`, `title`). Breach-monitoring feed data, if ingested, as `index=threatintel sourcetype=breach_feed`.

### Step-by-Step
1. **Build/confirm your watch-list lookup** (one-time setup, coordinate with HR/executive protection for the list).
2. **Check breach-monitoring feed for watch-list credentials.**
   ```spl
   index=threatintel sourcetype=breach_feed earliest=-30d
   | lookup executive_watchlist.csv email OUTPUT name, title
   | where isnotnull(name)
   | table _time, email, name, title, breach_source
   ```
3. **Filter email security logs for named-recipient targeting.**
   ```spl
   index=email action="blocked" OR action="quarantined" earliest=-7d
   | lookup executive_watchlist.csv recipient AS email OUTPUT name, title
   | where isnotnull(name)
   | table _time, sender, recipient, name, title, subject, verdict
   ```
4. **Search for impersonation profiles.** This is manual and happens outside Splunk: search LinkedIn and other social platforms for watch-list names, then log anything you find in a lookup (`impersonation_findings.csv`) so you can track it.

### If You Find Something
- **Watch-list member's credentials found in a fresh breach dump, or live impersonation profile found:** Escalate to IR, notify the individual directly, recommend credential rotation and hardware MFA.
- **A single targeted phishing attempt that was blocked:** Log it, share as an awareness heads-up, no urgent escalation if blocked successfully.

### Turn it into an alert
Save Step 3's query as a daily alert.


---

[← Collection index](README.md) · [Repository home](../README.md)
