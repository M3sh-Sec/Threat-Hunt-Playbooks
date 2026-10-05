# FS-13 Malicious Macro / HTA Delivery via Document Attachments

**MITRE ATT&CK:** T1204.002, T1566.001

**Plain-English summary:** A Word/Excel attachment (often disguised as a claim form or medical record) runs malicious code when opened with macros enabled.

### Prerequisites
- Splunk access to `index=endpoint` (process creation) and email sandbox detonation reports if ingested (`index=email sourcetype=*sandbox*`).

### Step-by-Step
1. **Hunt for Office apps spawning command-line tools.**
   ```spl
   index=endpoint earliest=-7d
   parent_process_name IN ("winword.exe","excel.exe","outlook.exe")
   process_name IN ("cmd.exe","powershell.exe","wscript.exe","mshta.exe")
   | table _time, host, user, parent_process_name, process_name, process_cmdline
   ```
2. **Review sandbox detonation results for high-risk intake mailboxes.**
   ```spl
   index=email sourcetype="*sandbox*" recipient="claims-intake@yourcompany.com" earliest=-7d verdict="malicious"
   | table _time, sender, attachment_name, verdict
   ```
3. **Check for follow-on network activity from flagged hosts.**
   ```spl
   index=endpoint earliest=-7d
   [ search index=endpoint parent_process_name IN ("winword.exe","excel.exe") process_name IN ("cmd.exe","powershell.exe","mshta.exe") earliest=-7d
     | fields host | dedup host ]
   | search sourcetype="network_connection"
   | table _time, host, dest_ip, dest_port
   ```

### If You Find Something
- **Confirmed Office-to-PowerShell/cmd chain with follow-on network activity:** Escalate to IR immediately, treat as active malware execution.
- **Sandbox flagged a malicious attachment that was blocked/never opened:** Log it, submit hash/sender to threat intel, no urgent escalation.

### Turn it into an alert
Save Step 1's query as a real-time or 15-minute alert.


---

[← Collection index](README.md) · [Repository home](../README.md)
