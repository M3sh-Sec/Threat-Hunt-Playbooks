# FS-10 SIM Swap Enabled MFA Bypass

**MITRE ATT&CK:** T1621, T1451

**Plain-English summary:** An attacker gets a victim's phone number ported to a SIM they control, letting them receive SMS-based one-time passcodes.

### Prerequisites
- Splunk access to `index=identity` (MFA method-change events) and `index=policyadmin`.

### Step-by-Step
1. **Pull MFA phone-number changes.**
   ```spl
   index=identity event_type="mfa_method_change" method="sms" earliest=-7d
   | table _time, user, old_phone, new_phone
   ```
2. **Check for a high-value transaction shortly after.**
   ```spl
   index=identity event_type="mfa_method_change" method="sms" earliest=-7d
   | rename _time AS mfa_change_time
   | join user
     [ search index=policyadmin action IN ("withdrawal","wire","beneficiary_change") earliest=-7d
       | eval txn_time=_time | table user, txn_time, action, amount ]
   | eval delta_hours=(txn_time-mfa_change_time)/3600
   | where delta_hours>=0 AND delta_hours<=48
   | table user, mfa_change_time, txn_time, action, amount, delta_hours
   ```
3. **Check for delayed OTP usage.**
   ```spl
   index=identity event_type IN ("otp_sent","otp_used") earliest=-7d
   | transaction user maxspan=1h
   | eval delay_minutes=(otp_used_time-otp_sent_time)/60
   | where delay_minutes>10
   | table user, otp_sent_time, otp_used_time, delay_minutes
   ```
   *(Field names for `otp_sent_time`/`otp_used_time` depend on how your MFA provider logs events, so adjust them to match your actual sourcetype.)*
4. **Cross-check customer complaint tickets** (if ingested into Splunk, e.g., `index=support`) for phrases like "lost service" or "new SIM."
   ```spl
   index=support earliest=-7d
   | search "lost service" OR "no signal" OR "new SIM" OR "SIM activated"
   | table _time, account_id, ticket_text
   ```

### If You Find Something
- **MFA phone change + pending high-value transaction:** Escalate to fraud team immediately, hold the transaction.
- **MFA phone change with no transaction yet:** Escalate as medium priority, proactively verify with the customer.

### Turn it into an alert
Save Step 2's query as an hourly alert.


---

[← Collection index](README.md) · [Repository home](../README.md)
