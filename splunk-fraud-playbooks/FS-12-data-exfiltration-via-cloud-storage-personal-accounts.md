# FS-12 — Data Exfiltration via Cloud Storage / Personal Accounts

**MITRE ATT&CK:** T1567

**Plain-English summary:** Someone copies large amounts of company data to a personal cloud storage account.

### Prerequisites
- Splunk access to `index=network` (proxy/CASB logs) and `index=endpoint` (for archive-creation detection).

### Step-by-Step
1. **Pull uploads to personal-tier cloud storage domains.**
   ```spl
   index=network sourcetype=proxy earliest=-7d
   | search dest_domain IN ("dropbox.com","drive.google.com","mega.nz","wetransfer.com") AND account_type!="corporate_sanctioned"
   | table _time, user, dest_domain, bytes_out
   ```
2. **Filter for volume and off-hours timing.**
   ```spl
   index=network sourcetype=proxy earliest=-7d dest_domain IN ("dropbox.com","drive.google.com","mega.nz","wetransfer.com")
   | eval hour=strftime(_time,"%H")
   | where bytes_out>100000000 OR hour<7 OR hour>19
   | table _time, user, dest_domain, bytes_out, hour
   ```
3. **Hunt for staged archives right before the upload.**
   ```spl
   index=endpoint process_name IN ("zip.exe","7z.exe","WinRAR.exe") earliest=-7d
   | rename _time AS archive_time
   | join user
     [ search index=network sourcetype=proxy dest_domain IN ("dropbox.com","drive.google.com","mega.nz") earliest=-7d
       | eval upload_time=_time | table user, upload_time, bytes_out ]
   | eval delta_min=(upload_time-archive_time)/60
   | where delta_min>=0 AND delta_min<=120
   | table user, archive_time, upload_time, bytes_out, delta_min
   ```
4. **Check DLP content classification, if available.**
   ```spl
   index=dlp earliest=-7d classification IN ("SSN","account_number","confidential")
   | table _time, user, destination, classification
   ```
5. **Cross-reference with HR departures** (reuse Playbook 7, Step 4's lookup pattern).

### If You Find Something
- **Large upload of sensitive content near a resignation date:** Escalate to IR and HR/Legal jointly.
- **Large upload, no sensitive content confirmed, plausible personal-use explanation:** Log it, no further action.

### Turn it into an alert
Save Step 3's query as a daily alert.


---

[← Collection index](README.md) · [Repository home](../README.md)
