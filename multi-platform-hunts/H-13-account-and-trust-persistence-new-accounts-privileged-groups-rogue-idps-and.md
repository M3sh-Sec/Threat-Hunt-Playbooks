# H-13 — Account and trust persistence: new accounts, privileged groups, rogue IdPs and OAuth grants (techniques 12–14)

**Hypothesis:** The intruder has created or elevated accounts in Active Directory, Entra or Okta, added a federated identity provider they control, or granted an OAuth application access to company data, so they can return even after passwords are reset.

**Data sources:** Domain controller Security log (4720, 4722, 4724, 4728, 4732, 4738, 4756), Defender for Identity `IdentityDirectoryEvents`, Falcon `UserAccountCreated` / `UserAccountAddedToGroup` and Falcon Identity Protection; Okta System Log; Entra `AuditLogs` (see Hunt 5 for Entra federation/consent queries).

**Steps**

1. Run 13A for new AD accounts and additions to privileged groups (Domain Admins, Enterprise Admins, Administrators, Schema Admins, Account Operators, Backup Operators, plus your own Tier 0 groups such as VMware/vCenter admins and CyberArk admins).
2. Run 13B for Okta identity-provider creation/changes and admin role grants. Scattered Spider has [added federated identity providers to victim SSO tenants](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a).
3. Re-run Hunt 5 Query 5A for Entra federation, consent and app credential events, and Hunt 8 for Salesforce connected apps.
4. Validate each change against a ticket. Pay attention to accounts named like service or vendor accounts and to changes made outside business hours.

**Query 13A — AD account creation and privileged group membership**

Splunk

```
index=wineventlog source="WinEventLog:Security" EventCode IN (4720, 4728, 4732, 4756)
| eval group=coalesce(Group_Name, TargetUserName)
| eval priv=if(match(group,"(?i)(Domain Admins|Enterprise Admins|Administrators|Schema Admins|Account Operators|Backup Operators|Server Operators|DnsAdmins|ESX Admins|vCenter|CyberArk)"),1,0)
| where EventCode=4720 OR priv=1
| table _time host EventCode Subject_Account_Name MemberName Target_Account_Name group priv
| sort - _time
```

CrowdStrike

```
#event_simpleName=/^(UserAccountCreated|UserAccountAddedToGroup)$/
| case { #event_simpleName=UserAccountAddedToGroup GroupRid=/^(512|518|519|544|548|551|549)$/ | Priv := 1;
         #event_simpleName=UserAccountAddedToGroup DomainGroupName=/(Domain Admins|Enterprise Admins|Administrators|Schema Admins|Account Operators|Backup Operators|ESX Admins|vCenter|CyberArk)/i | Priv := 1;
         * | Priv := 0 }
| #event_simpleName=UserAccountCreated OR Priv=1
| table([@timestamp, ComputerName, #event_simpleName, UserName, DomainGroupName, GroupRid, Priv])
```

KQL

```
let privGroups = @"(?i)(Domain Admins|Enterprise Admins|Administrators|Schema Admins|Account Operators|Backup Operators|Server Operators|DnsAdmins|ESX Admins|vCenter|CyberArk)";
SecurityEvent
| where TimeGenerated > ago(30d) and EventID in (4720, 4728, 4732, 4756)
| extend Group = iff(EventID == 4720, "", TargetUserName)
| where EventID == 4720 or Group matches regex privGroups
| project TimeGenerated, Computer, EventID, SubjectUserName, MemberName, TargetUserName, Group
| union (IdentityDirectoryEvents | where Timestamp > ago(30d) and ActionType == "Group Membership changed" | extend Group = tostring(AdditionalFields.["TO.GROUP"]) | where Group matches regex privGroups | project TimeGenerated = Timestamp, Computer = DestinationDeviceName, EventID = 0, SubjectUserName = AccountName, MemberName = TargetAccountDisplayName, TargetUserName = TargetAccountUpn, Group)
| order by TimeGenerated desc
```

Elastic (ES|QL)

```
FROM logs-system.security-*
| WHERE event.code IN ("4720","4728","4732","4756")
| EVAL group = CASE(event.code == "4720", "", group.name)
| WHERE event.code == "4720" OR group RLIKE """(?i).*(Domain Admins|Enterprise Admins|Administrators|Schema Admins|Account Operators|Backup Operators|Server Operators|DnsAdmins|ESX Admins|vCenter|CyberArk).*"""
| KEEP @timestamp, host.name, event.code, user.name, user.target.name, group
| SORT @timestamp DESC
```

**Query 13B — Okta identity-provider and admin-role changes**

Events: `system.idp.lifecycle.create`, `system.idp.lifecycle.update`, `system.idp.lifecycle.activate`, `user.account.privilege.grant`, `group.privilege.grant`, `application.lifecycle.create`, `app.oauth2.as.consent.grant`, `policy.lifecycle.update` (sign-on/MFA policy weakened), `system.api_token.create`.

Splunk: `index=okta sourcetype=OktaIM2:log eventType IN ("system.idp.lifecycle.create","system.idp.lifecycle.update","system.idp.lifecycle.activate","user.account.privilege.grant","group.privilege.grant","application.lifecycle.create","app.oauth2.as.consent.grant","policy.lifecycle.update","system.api_token.create") | table _time actor.alternateId client.ipAddress eventType target{}.displayName outcome.result`

CrowdStrike: `#Vendor="okta" | in(field="event.action", values=["system.idp.lifecycle.create","system.idp.lifecycle.update","system.idp.lifecycle.activate","user.account.privilege.grant","group.privilege.grant","application.lifecycle.create","app.oauth2.as.consent.grant","policy.lifecycle.update","system.api_token.create"]) | table([@timestamp, user.email, source.ip, event.action, Vendor.target[0].displayName])`

KQL: `OktaV2_CL | where TimeGenerated > ago(30d) and EventOriginalType in ("system.idp.lifecycle.create","system.idp.lifecycle.update","system.idp.lifecycle.activate","user.account.privilege.grant","group.privilege.grant","application.lifecycle.create","app.oauth2.as.consent.grant","policy.lifecycle.update","system.api_token.create") | project TimeGenerated, ActorUsername, SrcIpAddr, EventOriginalType, TargetUsername, EventResult`

Elastic ES|QL: `FROM logs-okta.system-* | WHERE okta.event_type IN ("system.idp.lifecycle.create","system.idp.lifecycle.update","system.idp.lifecycle.activate","user.account.privilege.grant","group.privilege.grant","application.lifecycle.create","app.oauth2.as.consent.grant","policy.lifecycle.update","system.api_token.create") | KEEP @timestamp, okta.actor.alternate_id, source.ip, okta.event_type, okta.target, okta.outcome.result`

**Common false positives:** provisioning from HR systems (Workday → AD/Okta), approved admin onboarding, Okta-to-Okta org federation. Any new external IdP is critical until proven otherwise.

---

[← Collection index](README.md) · [Repository home](../README.md)
