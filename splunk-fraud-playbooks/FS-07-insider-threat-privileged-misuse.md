# FS-07 Insider Threat / Privileged Misuse

**MITRE ATT&CK:** T1078.002

**Plain-English summary:** An employee/agent uses legitimate access to look at or take data they have no business reason to access.

### Prerequisites
- Splunk access to `index=policyadmin` (CRM/policy database access logs). Coordinate with HR for the termination/resignation list. Ask them for it as a lookup file (`hr_departures.csv`) instead of pulling it yourself.

### Step-by-Step
1. **Baseline per-role access volume** (run once, save the output as a reference, don't need to re-run often).
   ```spl
   index=policyadmin earliest=-90d
   | stats count AS daily_avg by user_role
   | eventstats avg(daily_avg) AS role_baseline by user_role
   ```
2. **Hunt for out-of-scope territory access.**
   ```spl
   index=policyadmin earliest=-7d
   | where accessed_territory!=assigned_territory
   | stats count by user, accessed_territory, assigned_territory
   | sort -count
   ```
3. **Hunt for bulk export activity.**
   ```spl
   index=policyadmin action=export earliest=-7d
   | stats sum(record_count) AS total_exported by user
   | sort -total_exported
   | where total_exported>1000
   ```
   *(Tune `1000` to your baseline from Step 1.)*
4. **Correlate with HR departures.**
   ```spl
   index=policyadmin action=export earliest=-30d
   | lookup hr_departures.csv user OUTPUT last_day
   | where isnotnull(last_day)
   | eval days_from_departure=abs((strptime(last_day,"%Y-%m-%d")-_time)/86400)
   | where days_from_departure<=14
   | table _time, user, record_count, last_day, days_from_departure
   ```
5. **Hunt for VIP/employee-owned record access.**
   ```spl
   index=policyadmin earliest=-7d
   | lookup vip_policy_accounts.csv account_id OUTPUT is_vip
   | where is_vip=1 AND assigned_servicer!=user
   | table _time, user, account_id, action
   ```

### If You Find Something
- **Bulk export correlated with upcoming/recent departure:** Escalate to IR and HR/Legal jointly.
- **Curiosity access to a VIP record:** Escalate to HR/Legal per your internal policy.

### Turn it into an alert
Save Step 4's query as a daily alert (this needs `hr_departures.csv` refreshed regularly, so set up a feed or a weekly manual update with HR).


---

[← Collection index](README.md) · [Repository home](../README.md)
