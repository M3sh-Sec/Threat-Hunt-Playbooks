# FS-09 — Vishing / Call-Center Social Engineering

**MITRE ATT&CK:** T1598, T1656

**Plain-English summary:** An attacker calls the call center pretending to be a policyholder, using researched personal info to pass identity verification, then changes contact info or requests a withdrawal.

### Prerequisites
- Splunk access to `index=callcenter` (CRM call records with verification results) and `index=policyadmin`.

### Step-by-Step
1. **Pull phone-channel contact changes.**
   ```spl
   index=policyadmin channel="phone" change_type IN ("address","phone","email","beneficiary") earliest=-7d
   | table _time, account_id, change_type, agent_id
   ```
2. **Check for a withdrawal/loan/beneficiary request within 72 hours of the change (the single most important query in this playbook).**
   ```spl
   index=policyadmin channel="phone" change_type IN ("address","phone","email","beneficiary") earliest=-7d
   | rename _time AS change_time
   | join account_id
     [ search index=policyadmin action IN ("withdrawal","loan","beneficiary_change") earliest=-7d
       | eval request_time=_time | table account_id, request_time, action ]
   | eval delta_hours=(request_time-change_time)/3600
   | where delta_hours>=0 AND delta_hours<=72
   | table account_id, change_time, change_type, request_time, action, delta_hours
   ```
3. **Hunt for repeat calls with different caller ID.**
   ```spl
   index=callcenter earliest=-7d
   | stats dc(caller_id) AS distinct_callers, count AS call_count by account_id
   | where distinct_callers>=2 AND call_count>=3
   ```
4. **Hunt for failed-then-passed verification.**
   ```spl
   index=callcenter earliest=-7d
   | transaction account_id maxspan=48h
   | search verification_result="fail" verification_result="pass"
   | table account_id, _time, duration, eventcount
   ```
5. **Review notes/recordings for shortlisted calls** — manual step, use the `account_id` list from Steps 2-4 to pull specific call records for review.

### If You Find Something
- **Change-then-withdraw pattern, transaction still pending:** Escalate to fraud team immediately to hold the transaction.
- **Repeat-call pattern, no completed transaction yet:** Escalate as medium priority; flag the account for enhanced verification for 30 days.

### Turn it into an alert
Save Step 2's query as an hourly alert — route directly to the fraud team's queue given the time sensitivity.


---

[← Collection index](README.md) · [Repository home](../README.md)
