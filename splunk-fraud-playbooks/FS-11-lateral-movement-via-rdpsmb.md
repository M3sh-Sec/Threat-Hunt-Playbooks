# FS-11 — Lateral Movement via RDP/SMB

**MITRE ATT&CK:** T1021.001, T1021.002

**Plain-English summary:** An attacker with a foothold on one machine "hops" to others using RDP or SMB.

### Prerequisites
- Splunk ingesting Windows Security Event Logs (`sourcetype=WinEventLog:Security`) with Event IDs 4624/4625/4648/4769 enabled, plus a lookup `approved_jump_hosts.csv`.

### Step-by-Step
1. **Hunt for workstation-to-workstation RDP (Logon Type 10), excluding known jump hosts.**
   ```spl
   index=endpoint sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=10 earliest=-7d
   | lookup approved_jump_hosts.csv host AS src_host OUTPUT is_jump_host
   | where isnull(is_jump_host)
   | table _time, src_host, dest_host, user
   ```
2. **Flag local admin account usage over the network.**
   ```spl
   index=endpoint sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type IN (3,10) earliest=-7d
   | regex user="^[^\\\\]+\\\\Administrator$|^\\.\\\\Administrator$"
   | table _time, src_host, dest_host, user, Logon_Type
   ```
3. **Hunt for admin share access outside patch/backup windows.**
   ```spl
   index=endpoint sourcetype="WinEventLog:Security" EventCode=5140 Share_Name IN ("\\\\*\\C$","\\\\*\\ADMIN$") earliest=-7d
   | lookup patch_schedule.csv host OUTPUT scheduled_window_start, scheduled_window_end
   | eval hour=strftime(_time,"%H")
   | where hour<scheduled_window_start OR hour>scheduled_window_end
   | table _time, host, Share_Name, user
   ```
4. **Hunt for Kerberoasting indicators.**
   ```spl
   index=endpoint sourcetype="WinEventLog:Security" EventCode=4769 earliest=-7d Ticket_Encryption_Type=0x17
   | stats count by Account_Name, Service_Name
   | where count>10
   ```

### If You Find Something
- **Workstation-to-workstation RDP using local admin, not tied to known IT activity:** Escalate to IR as likely active lateral movement — treat with urgency.
- **Isolated admin share access with a plausible explanation:** Log it, verify with IT, close if confirmed legitimate.

### Turn it into an alert
Save Step 1's query as a 15-minute scheduled alert.


---

[← Collection index](README.md) · [Repository home](../README.md)
