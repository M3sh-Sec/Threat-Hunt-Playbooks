# 14. API Abuse for Automated Account Enumeration/Takeover

[← Back to index](../README.md)

**Plain-English summary:** Attackers script requests against your mobile app/partner APIs to guess valid member numbers or abuse password-reset functions.

### Prerequisites
- Splunk access to `index=api` (API gateway logs).

### Step-by-Step
1. **Pull request volume by API key/IP for sensitive endpoints.**
   ```spl
   index=api uri_path IN ("/member/lookup","/password/reset","/otp/request") earliest=-7d
   | stats count by api_key, client_ip, uri_path
   | sort -count
   ```
2. **Hunt for parameter sweeps.**
   ```spl
   index=api uri_path="/member/lookup" earliest=-7d
   | rex field=uri_query "memberId=(?<member_id>\d+)"
   | sort 0 client_ip, _time
   | streamstats current=f last(member_id) AS prev_id by client_ip
   | eval diff=member_id-prev_id
   | where diff=1
   | stats count AS sequential_lookups by client_ip, api_key
   | where sequential_lookups>=10
   ```
3. **Compare partner traffic to documented normal pattern.**
   ```spl
   index=api earliest=-7d
   | lookup partner_integration_profile.csv api_key OUTPUT expected_volume, expected_ip_range, expected_hours
   | stats count AS actual_volume by api_key, expected_volume
   | eval variance_pct=round((actual_volume-expected_volume)/expected_volume*100,1)
   | where abs(variance_pct)>200
   ```
4. **Hunt for password-reset/OTP abuse across many accounts.**
   ```spl
   index=api uri_path IN ("/password/reset","/otp/request") earliest=-7d
   | stats dc(target_account) AS distinct_targets by client_ip
   | where distinct_targets>20
   ```

### If You Find Something
- **Confirmed parameter sweep against member-lookup endpoint returning real data:** Escalate to IR and engineering immediately.
- **API key traffic anomaly with a plausible business explanation:** Verify with the partner/integration owner, log outcome.

### Turn it into an alert
Save Step 2's query as an hourly alert.

---

