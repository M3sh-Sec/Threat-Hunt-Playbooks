# H-05 Azure and Entra ID persistence

**Hypothesis:** After compromising an Entra ID account (help-desk social engineering, MFA fatigue, AiTM phishing or token theft), an adversary has set up persistence. On the identity side that means new MFA methods or devices, app or service-principal credentials, consented OAuth apps, federated domains, or privileged role assignments. On the resource side it means RBAC grants, VM extensions and Automation runbooks.

**ATT&CK:** T1098.005 Device Registration, T1556.006 MFA modification, T1098.001 Additional Cloud Credentials, T1098.003 Additional Cloud Roles, T1484.002 Domain/Tenant Trust Modification, T1528 Steal Application Access Token (illicit consent), T1136.003 Cloud Account, T1078.004 Cloud Accounts.

**Data sources**

| Source | Splunk | Sentinel | Elastic | CrowdStrike |
| --- | --- | --- | --- | --- |
| Entra audit logs | `azure:aad:audit` (MS Cloud Services / Graph add-on) | `AuditLogs` | `logs-azure.auditlogs-*` | NG-SIEM Entra ID connector; Falcon Identity Protection |
| Entra sign-in logs | `azure:aad:signin` | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs` | `logs-azure.signinlogs-*` | NG-SIEM Entra ID connector |
| Azure Activity (control plane) | `mscs:azure:eventhub` / `azure:monitor:activity` | `AzureActivity` | `logs-azure.activitylogs-*` | NG-SIEM Azure connector |
| Graph activity (optional, high value) | Event Hub | `MicrosoftGraphActivityLogs` | Event Hub integration | NG-SIEM |

**Steps**

1. Run 5A for identity-plane persistence operations over 30 days and group by initiating actor.
2. For every "User registered security info" or "Register device" event, check the sign-in that preceded it: new IP/ASN, new country, help-desk password reset or MFA reset in the prior 24 hours (classic Scattered Spider pattern).
3. For app credential and consent events, check whether the app is first-party, who owns it, what Graph permissions it holds (`Mail.Read`, `Files.ReadWrite.All`, `Directory.ReadWrite.All`, `full_access_as_app`) and whether the service principal then signed in from a new IP.
4. Treat "Set domain authentication" / "Set federation settings on domain" as critical: a rogue federated domain lets the attacker mint tokens for any user.
5. Run 5B for Azure resource-plane changes (role assignments, VM run commands/extensions, Automation, Function app keys).
6. Confirm or rule out with the user and the change ticket; revoke sessions (`Revoke-MgUserSignInSession`) and remove artifacts if malicious.

**Query 5A: Entra ID identity-plane persistence operations**

Operations: `User registered security info, User registered all required security info, Admin registered security info, Register device, Add registered owner to device, Add service principal credentials, Update application – Certificates and secrets management, Add owner to application, Add owner to service principal, Consent to application, Add delegated permission grant, Add app role assignment to service principal, Add member to role, Add eligible member to role, Add user, Invite external user, Set domain authentication, Set federation settings on domain, Add unverified domain, Update conditional access policy, Delete conditional access policy, Update cross-tenant access settings`.

Splunk

```
index=azure sourcetype=azure:aad:audit
  activityDisplayName IN ("User registered security info","Admin registered security info","Register device","Add registered owner to device","Add service principal credentials","Update application – Certificates and secrets management","Add owner to application","Add owner to service principal","Consent to application","Add delegated permission grant","Add app role assignment to service principal","Add member to role","Add eligible member to role","Add user","Invite external user","Set domain authentication","Set federation settings on domain","Add unverified domain","Update conditional access policy","Delete conditional access policy","Update cross-tenant access settings")
| eval actor=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName'), target=mvindex('targetResources{}.userPrincipalName',0), target_name=mvindex('targetResources{}.displayName',0)
| stats count min(_time) as first_seen values(activityDisplayName) as ops values(initiatedBy.user.ipAddress) as ips by actor target target_name
| convert ctime(first_seen)
| sort - count
```

CrowdStrike (NG-SIEM)

```
#Vendor="microsoft" #event.module=/entra|azure/i
| in(field="event.action", values=["User registered security info","Admin registered security info","Register device","Add registered owner to device","Add service principal credentials","Update application – Certificates and secrets management","Add owner to application","Add owner to service principal","Consent to application","Add delegated permission grant","Add app role assignment to service principal","Add member to role","Add eligible member to role","Add user","Invite external user","Set domain authentication","Set federation settings on domain","Add unverified domain","Update conditional access policy","Delete conditional access policy","Update cross-tenant access settings"], ignoreCase=true)
| groupBy([user.name, event.action], function=[count(), min(@timestamp, as=FirstSeen), collect([source.ip], limit=10)])
| sort(FirstSeen, order=desc)
```

KQL

```
let ops = dynamic(["User registered security info","Admin registered security info","Register device","Add registered owner to device","Add service principal credentials","Update application – Certificates and secrets management","Add owner to application","Add owner to service principal","Consent to application","Add delegated permission grant","Add app role assignment to service principal","Add member to role","Add eligible member to role","Add user","Invite external user","Set domain authentication","Set federation settings on domain","Add unverified domain","Update conditional access policy","Delete conditional access policy","Update cross-tenant access settings"]);
AuditLogs
| where TimeGenerated > ago(30d) and OperationName in (ops) and Result == "success"
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),
         ActorIP = tostring(InitiatedBy.user.ipAddress),
         Target = coalesce(tostring(TargetResources[0].userPrincipalName), tostring(TargetResources[0].displayName))
| join kind=leftouter (
    SigninLogs | where TimeGenerated > ago(30d) and ResultType == 0
    | summarize KnownIPs = make_set(IPAddress, 50) by UserPrincipalName
  ) on $left.Actor == $right.UserPrincipalName
| extend NewIP = iff(isnotempty(ActorIP) and not(set_has_element(KnownIPs, ActorIP)), true, false)
| project TimeGenerated, OperationName, Actor, ActorIP, NewIP, Target, CorrelationId
| order by NewIP desc, TimeGenerated desc
```

Elastic (ES|QL)

```
FROM logs-azure.auditlogs-*
| WHERE event.outcome == "success" AND azure.auditlogs.operation_name IN ("User registered security info","Admin registered security info","Register device","Add registered owner to device","Add service principal credentials","Update application – Certificates and secrets management","Add owner to application","Add owner to service principal","Consent to application","Add delegated permission grant","Add app role assignment to service principal","Add member to role","Add eligible member to role","Add user","Invite external user","Set domain authentication","Set federation settings on domain","Add unverified domain","Update conditional access policy","Delete conditional access policy","Update cross-tenant access settings")
| EVAL actor = COALESCE(azure.auditlogs.properties.initiated_by.user.userPrincipalName, azure.auditlogs.properties.initiated_by.app.displayName)
| STATS c = COUNT(*), first_seen = MIN(@timestamp), ops = VALUES(azure.auditlogs.operation_name), ips = VALUES(source.ip) BY actor
| SORT first_seen DESC
```

**Query 5A-2: MFA method added shortly after a password or MFA reset (help-desk takeover pattern)**

KQL (adapt the same two-event sequence to Splunk `transaction`, Elastic EQL `sequence`, or CrowdStrike `correlate()`)

```
let resets = AuditLogs
| where TimeGenerated > ago(30d) and OperationName in ("Reset user password","Reset password (by admin)","Admin deleted security info","Update user")
| extend Target = tostring(TargetResources[0].userPrincipalName), ResetBy = tostring(InitiatedBy.user.userPrincipalName), ResetTime = TimeGenerated;
AuditLogs
| where TimeGenerated > ago(30d) and OperationName in ("User registered security info","Register device")
| extend Target = coalesce(tostring(TargetResources[0].userPrincipalName), tostring(InitiatedBy.user.userPrincipalName)), RegTime = TimeGenerated, RegIP = tostring(InitiatedBy.user.ipAddress)
| join kind=inner resets on Target
| where RegTime between (ResetTime .. (ResetTime + 24h))
| project Target, ResetBy, ResetTime, RegTime, OperationName, RegIP
```

Elastic EQL

```
sequence by azure.auditlogs.properties.target_resources.0.user_principal_name with maxspan=24h
  [any where event.dataset == "azure.auditlogs" and azure.auditlogs.operation_name : ("Reset user password", "Reset password (by admin)", "Admin deleted security info")]
  [any where event.dataset == "azure.auditlogs" and azure.auditlogs.operation_name : ("User registered security info", "Register device")]
```

**Query 5B: Azure control-plane persistence (RBAC, VM extensions/run command, Automation, Functions)**

Operations: `Microsoft.Authorization/roleAssignments/write, Microsoft.Authorization/roleDefinitions/write, Microsoft.Compute/virtualMachines/extensions/write, Microsoft.Compute/virtualMachines/runCommand/action, Microsoft.Automation/automationAccounts/runbooks/write, Microsoft.Automation/automationAccounts/webhooks/write, Microsoft.Web/sites/functions/write, Microsoft.Web/sites/host/listkeys/action, Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write, Microsoft.Insights/diagnosticSettings/delete`.

Splunk

```
index=azure sourcetype IN (mscs:azure:eventhub, azure:monitor:activity) 
| eval op=upper(coalesce(operationName.value, operationName))
| search op IN ("MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE","MICROSOFT.AUTHORIZATION/ROLEDEFINITIONS/WRITE","MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE","MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION","MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/WRITE","MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/WRITE","MICROSOFT.WEB/SITES/FUNCTIONS/WRITE","MICROSOFT.WEB/SITES/HOST/LISTKEYS/ACTION","MICROSOFT.MANAGEDIDENTITY/USERASSIGNEDIDENTITIES/FEDERATEDIDENTITYCREDENTIALS/WRITE","MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE")
| stats count min(_time) as first_seen values(resourceId) as resources values(callerIpAddress) as ips by caller op
| convert ctime(first_seen)
```

CrowdStrike (NG-SIEM)

```
#Vendor="microsoft" event.action=/(roleAssignments\/write|roleDefinitions\/write|virtualMachines\/extensions\/write|runCommand\/action|runbooks\/write|webhooks\/write|sites\/functions\/write|host\/listkeys\/action|federatedIdentityCredentials\/write|diagnosticSettings\/delete)/i
| groupBy([user.name, event.action], function=[count(), min(@timestamp, as=FirstSeen), collect([source.ip], limit=10)])
```

KQL

```
AzureActivity
| where TimeGenerated > ago(30d) and ActivityStatusValue in ("Success","Succeeded")
| where OperationNameValue has_any ("roleAssignments/write","roleDefinitions/write","virtualMachines/extensions/write","runCommand/action","runbooks/write","webhooks/write","sites/functions/write","host/listkeys/action","federatedIdentityCredentials/write","diagnosticSettings/delete")
| summarize Count = count(), FirstSeen = min(TimeGenerated), Resources = make_set(_ResourceId, 20), IPs = make_set(CallerIpAddress, 10) by Caller, OperationNameValue
| order by FirstSeen desc
```

Elastic (ES|QL)

```
FROM logs-azure.activitylogs-*
| WHERE event.outcome == "success"
| WHERE TO_LOWER(azure.activitylogs.operation_name) RLIKE """.*(roleassignments/write|roledefinitions/write|virtualmachines/extensions/write|runcommand/action|runbooks/write|webhooks/write|sites/functions/write|host/listkeys/action|federatedidentitycredentials/write|diagnosticsettings/delete).*"""
| STATS c = COUNT(*), first_seen = MIN(@timestamp), ips = VALUES(source.ip) BY azure.activitylogs.identity.claims_initiated_by_user.name, azure.activitylogs.operation_name
```

**Common false positives:** Intune/Autopilot device registrations, self-service MFA enrollment campaigns, IaC pipelines assigning roles, Microsoft first-party apps rotating credentials. Focus on events from new IPs, outside business hours, or initiated by recently reset accounts.

---

[← Collection index](README.md) · [Repository home](../README.md)
