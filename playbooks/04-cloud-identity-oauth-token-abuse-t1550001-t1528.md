# 4. Cloud Identity / OAuth Token Abuse (T1550.001, T1528)

[← Back to index](../README.md)

**Plain-English summary:** An attacker tricks a user into approving a malicious third-party app's access request, gaining persistent access to mail/files that survives a password reset.

### Prerequisites
- Splunk ingesting Azure AD audit logs / O365 Management Activity API (`index=identity sourcetype=o365:management:audit` or `azuread:audit`, depending on your add-on).

### Step-by-Step
1. **Pull consent grant events from the last 90 days.**
   ```spl
   index=identity sourcetype="o365:management:audit" Operation="Consent to application*" earliest=-90d
   | table _time, UserId, ApplicationDisplayName, Scope, ConsentType
   ```
2. **Flag broad/high-risk scopes.**
   ```spl
   index=identity sourcetype="o365:management:audit" Operation="Consent to application*" earliest=-90d
   | search Scope="*Mail.Read*" OR Scope="*Mail.ReadWrite*" OR Scope="*Files.ReadWrite.All*" OR Scope="*Directory.Read.All*" OR Scope="*offline_access*"
   | table _time, UserId, ApplicationDisplayName, Scope
   ```
3. **Check publisher verification status and consent recency.**
   ```spl
   index=identity sourcetype="o365:management:audit" Operation="Consent to application*" earliest=-90d
   | lookup verified_publishers.csv ApplicationId OUTPUT is_verified
   | where isnull(is_verified)
   | stats count AS consent_count, values(UserId) AS users, latest(_time) AS last_consent by ApplicationDisplayName, ApplicationId
   | convert ctime(last_consent)
   | sort -consent_count
   ```
   *(Build `verified_publishers.csv` yourself from your IT-approved app list, or skip this lookup and just eyeball unfamiliar app names.)*
4. **Look for a sudden spike — same app, multiple new consents recently.**
   ```spl
   index=identity sourcetype="o365:management:audit" Operation="Consent to application*" earliest=-14d
   | stats dc(UserId) AS recent_consents by ApplicationDisplayName
   | where recent_consents>=3
   ```
5. **Correlate consenting users with sign-in anomalies** (reuse Playbook 1, Step 4's join pattern, substituting consent time for click time).

### If You Find Something
- **Live suspicious app with recent/multiple consents:** Escalate to IR immediately — revoke the app's access org-wide and force-refresh tokens.
- **Single old consent, low-risk scope:** Log it, recommend periodic app-consent review as a hygiene item.

### Turn it into an alert
Save Step 4's query as a weekly alert: "if number of results > 0."

---

