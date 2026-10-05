# FS-08 Web Application Attacks Against Customer Portals

**MITRE ATT&CK:** T1190

**Plain-English summary:** Attackers probe your customer-facing portal for bugs that expose other customers' data or bypass authentication.

### Prerequisites
- Splunk access to `index=waf` and `index=app` (application logs).

### Step-by-Step
1. **Hunt for sequential/incrementing ID parameters (IDOR probing).**
   ```spl
   index=app earliest=-7d
   | rex field=uri_query "policyId=(?<policy_id>\d+)"
   | where isnotnull(policy_id)
   | sort 0 client_ip, _time
   | streamstats current=f last(policy_id) AS prev_id by client_ip
   | eval diff=policy_id-prev_id
   | where diff=1
   | stats count AS sequential_requests by client_ip
   | where sequential_requests>=5
   ```
2. **Hunt for high 401/403 burst followed by a 200.**
   ```spl
   index=waf earliest=-7d
   | stats count(eval(status=401 OR status=403)) AS denied, count(eval(status=200)) AS allowed by client_ip, session_id
   | where denied>10 AND allowed>0
   | sort -denied
   ```
3. **Review blocked SQLi/XSS attempts and rank by pattern diversity.**
   ```spl
   index=waf action=blocked earliest=-7d
   | stats dc(attack_signature) AS distinct_payload_types, count AS total_blocks by client_ip
   | sort -distinct_payload_types
   ```
4. **Check for a later success from a previously-blocked IP.**
   ```spl
   index=waf earliest=-7d
   | stats count(eval(action="blocked")) AS blocks, count(eval(action="allowed" AND status=200)) AS later_success by client_ip
   | where blocks>0 AND later_success>0
   ```

### If You Find Something
- **Evidence of successful IDOR access to another customer's data:** Escalate to IR and legal/compliance immediately (possible breach notification obligation).
- **Blocked probing with no successful bypass:** Log as reconnaissance, share IPs with the network team for blocklist review.

### Turn it into an alert
Save Step 1's query as a 30-minute scheduled alert.


---

[← Collection index](README.md) · [Repository home](../README.md)
