# 6. Third-Party / Vendor Supply Chain Compromise (T1195)

[← Back to index](../README.md)

**Plain-English summary:** A vendor with trusted access to your environment gets compromised, and the attacker uses that trusted connection to get in.

### Prerequisites
- Splunk access to `index=network` (VPN logs) and a lookup table `vendor_access_inventory.csv` (columns: `account`, `vendor_name`, `approved_resources`, `expected_hours`, `expected_ip_range`).

### Step-by-Step
1. **Build/confirm your vendor inventory lookup** (this is a one-time setup task, not a search — populate `vendor_access_inventory.csv` from procurement/IT asset records).
2. **Check for access outside documented scope.**
   ```spl
   index=network sourcetype=vpn earliest=-30d
   | lookup vendor_access_inventory.csv account OUTPUT approved_resources, vendor_name
   | where isnotnull(vendor_name)
   | eval out_of_scope=if(like(approved_resources, "%".resource."%"), 0, 1)
   | where out_of_scope=1
   | table _time, account, vendor_name, resource, approved_resources
   ```
3. **Check for anomalous login timing/source IP per vendor.**
   ```spl
   index=network sourcetype=vpn earliest=-30d
   | lookup vendor_access_inventory.csv account OUTPUT expected_hours, expected_ip_range, vendor_name
   | where isnotnull(vendor_name)
   | eval hour=strftime(_time,"%H")
   | eval outside_hours=if(hour<expected_hours_start OR hour>expected_hours_end, 1, 0)
   | table _time, account, vendor_name, src_ip, hour, outside_hours
   ```
   *(Simplify by splitting `expected_hours` into `expected_hours_start`/`expected_hours_end` columns in your lookup CSV.)*
4. **Check for privilege beyond integration need.**
   ```spl
   index=identity sourcetype="account_permissions" earliest=-1d
   | lookup vendor_access_inventory.csv account OUTPUT approved_resources
   | where isnotnull(approved_resources)
   | eval excess=if(match(granted_permissions, approved_resources), 0, 1)
   | where excess=1
   | table account, vendor_name, granted_permissions, approved_resources
   ```
5. **Vendor breach news monitoring** — this step is done outside Splunk (manual web search or a threat-intel feed), but you can log findings into a Splunk lookup (`vendor_breach_watch.csv`) and join it against Step 2's output to auto-prioritize.

### If You Find Something
- **Active anomalous access from a vendor account:** Escalate to IR; recommend temporarily suspending that vendor's access.
- **Over-provisioned but no misuse:** Log as a risk finding, route to IT/vendor management.

### Turn it into an alert
Save Step 2's query as a daily alert.

---

