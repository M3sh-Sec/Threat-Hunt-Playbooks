# 3. Valid Account Abuse / Credential Stuffing (T1078, T1110.004)

[← Back to index](../README.md)

**Plain-English summary:** Attackers try leaked email/password pairs from other companies' breaches against your customer or agent login portal.

### Prerequisites
- Splunk access to `index=waf` and `index=identity` (portal authentication events). If your environment has the CIM **Authentication** data model built, you can use `tstats` for speed on large volumes.

### Step-by-Step
1. **Failed login volume by source IP.**
   ```spl
   index=identity sourcetype=portal_auth action=failure earliest=-7d
   | stats count by src_ip
   | sort -count
   ```
2. **Find the low-and-slow pattern: many IPs, one or two attempts each, across many usernames.**
   ```spl
   index=identity sourcetype=portal_auth action=failure earliest=-7d
   | stats count AS attempts by src_ip, user
   | where attempts<=2
   | stats dc(user) AS unique_users_targeted, count AS total_attempts by src_ip
   | where unique_users_targeted>=1
   | sort -unique_users_targeted
   ```
   *(If your WAF/threat intel add-on tags IP type, add `| lookup ip_reputation.csv src_ip OUTPUT ip_type` and filter `ip_type IN ("hosting","proxy","vpn")` to prioritize.)*
3. **Find successful logins buried among failures (the "needle in the haystack").**
   ```spl
   index=identity sourcetype=portal_auth earliest=-7d
   | stats count(eval(action="failure")) AS fails, count(eval(action="success")) AS successes by user
   | where fails>5 AND successes>0
   | sort -fails
   ```
   *Using the CIM Authentication data model instead (faster on large volumes):*
   ```spl
   | tstats count(eval(Authentication.action="failure")) AS fails, count(eval(Authentication.action="success")) AS successes FROM datamodel=Authentication WHERE earliest=-7d BY Authentication.user
   | rename Authentication.user AS user
   | where fails>5 AND successes>0
   ```
4. **Check for account changes right after a successful login from Step 3.**
   ```spl
   index=policyadmin earliest=-7d
   | join user
     [ search index=identity sourcetype=portal_auth action=success earliest=-7d
       | eval login_time=_time | table user, login_time ]
   | eval delta_hours=(_time-login_time)/3600
   | where delta_hours>=0 AND delta_hours<=24
   | table user, login_time, _time, change_type, delta_hours
   ```
5. **(Optional) Correlate with breach-monitoring feed if you have one ingested into Splunk as a lookup** — join `user`/email against `known_breach_emails.csv`.

### If You Find Something
- **Successful login + immediate account change:** Escalate to IR/fraud as account-takeover-in-progress.
- **High failed-attempt volume, no successes:** Log it, recommend rate-limiting/CAPTCHA tuning to the web team via ticket, no individual escalation needed.

### Turn it into an alert
Save Step 3's query as a daily alert: "if number of results > 0."

---

