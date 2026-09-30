# 5. Ransomware Precursor Activity (T1486, T1490, TA0040)

[← Back to index](../README.md)

**Plain-English summary:** Before ransomware encrypts files, attackers usually delete backups and explore the network for days-to-weeks. Catching this before encryption is the goal.

### Prerequisites
- Splunk ingesting EDR process events (`index=endpoint sourcetype=crowdstrike` or Windows Security logs `sourcetype=WinEventLog:Security`).

### Step-by-Step
1. **Hunt for shadow-copy/backup deletion commands.**
   ```spl
   index=endpoint earliest=-7d
   (process_cmdline="*vssadmin*delete*shadows*" OR process_cmdline="*wmic*shadowcopy*delete*" OR process_cmdline="*wbadmin*delete*catalog*" OR process_cmdline="*bcdedit*recoveryenabled*no*")
   | table _time, host, user, process_cmdline
   ```
2. **Hunt for mass file enumeration** (requires file server audit logging, e.g., Windows Object Access events or a file-integrity/audit tool feeding Splunk).
   ```spl
   index=endpoint sourcetype="filesystem_audit" earliest=-7d action=read
   | bucket _time span=10m
   | stats count AS files_touched by _time, user
   | where files_touched>500
   ```
   *(Tune the `500` threshold to your actual baseline — run this same search over a known-quiet week first to see typical values.)*
3. **Hunt for unapproved remote access tooling installs/execution.**
   ```spl
   index=endpoint earliest=-7d
   process_name IN ("AnyDesk.exe","TeamViewer.exe","ScreenConnect.exe","*.msi")
   | lookup approved_software.csv process_name OUTPUT approved
   | where isnull(approved)
   | table _time, host, user, process_name, process_cmdline
   ```
4. **Hunt for security tooling tampering.**
   ```spl
   index=endpoint earliest=-7d
   (process_cmdline="*sc stop*" OR process_cmdline="*net stop*") AND process_cmdline IN ("*Defender*","*CrowdStrike*","*Sophos*","*antivirus*")
   | table _time, host, user, process_cmdline
   ```
5. **Time-correlate all four signals on the same host.**
   ```spl
   (index=endpoint earliest=-48h process_cmdline="*vssadmin*delete*shadows*")
   OR (index=endpoint earliest=-48h process_name IN ("AnyDesk.exe","TeamViewer.exe"))
   | stats dc(search_name) AS distinct_signals values(search_name) AS signals by host
   | where distinct_signals>=2
   ```
   *(For a cleaner version of this, build each individual hunt as a saved search, then use Splunk's "Risk-Based Alerting" in Enterprise Security to auto-sum risk scores per host — ask your Splunk admin if ES is available.)*

### If You Find Something
- **Any single strong signal (backup deletion, especially):** Escalate to IR **immediately** — do not wait to confirm all signals.
- **Weaker signal alone:** Escalate as medium priority same business day.

### Turn it into an alert
Save Step 1's query as a **real-time or 15-minute scheduled alert** — this is the single highest-value alert in this entire document given how rarely it fires legitimately.

---

