# H-04 — AWS persistence

**Hypothesis:** An attacker holding stolen AWS credentials (from a developer laptop, CI secret, SSO session hijack or exposed access key) has created durable access — new IAM users or access keys, modified role trust policies, new identity providers, or serverless/compute backdoors — that will survive the original credential being revoked.

**ATT&CK:** T1098.001 Additional Cloud Credentials, T1136.003 Cloud Account, T1098.003 Additional Cloud Roles, T1484.002 Trust Modification (SAML/OIDC providers), T1546 / T1525 (Lambda and AMI/user-data backdoors), T1562.008 Disable Cloud Logs.

**Data sources**

| Source | Notes |
| --- | --- |
| CloudTrail (management events, all regions, org trail) | Required. Splunk Add-on for AWS (`aws:cloudtrail`), Sentinel `AWSCloudTrail`, Elastic `logs-aws.cloudtrail-*`, CrowdStrike NG-SIEM AWS connector |
| IAM Identity Center / Organizations events | Account assignments and permission-set changes |
| GuardDuty findings | `Persistence:IAMUser/*`, `CredentialAccess:*`, `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` |
| CrowdStrike Falcon Cloud Security | CIEM/IOA detections can be pivoted alongside these queries |

CrowdStrike NG-SIEM field names depend on the AWS parser; queries below use the normalized `event.action`, `user.name`, `source.ip`. Raw CloudTrail fields are under `Vendor.*` (for example `Vendor.eventName`).

**Steps**

1. Run 4A for the persistence API calls over 30 days. Stack by `principal + eventName`; anything an identity has never done before is a lead.
2. Run 4B for the highest-signal patterns: an identity creating access keys or login profiles for a *different* user, trust policies that name an external account, and new SAML/OIDC providers.
3. Enrich each lead with the source IP (ASN, geo, VPN/hosting provider), user agent (CLI vs. console vs. SDK vs. unusual tooling like `Boto3` from residential IP) and the session's preceding `ConsoleLogin` / `AssumeRole` / `GetSessionToken` events.
4. Check whether logging was tampered with in the same session (`StopLogging`, `DeleteTrail`, `PutEventSelectors`, `DeleteDetector`).
5. For confirmed malicious changes, inventory every resource the principal touched and rotate credentials of every identity it could assume.

**Query 4A — IAM, identity and compute persistence API calls**

Event list used below: `CreateUser, CreateAccessKey, CreateLoginProfile, UpdateLoginProfile, AttachUserPolicy, PutUserPolicy, AddUserToGroup, CreateRole, UpdateAssumeRolePolicy, AttachRolePolicy, PutRolePolicy, CreatePolicyVersion, SetDefaultPolicyVersion, CreateSAMLProvider, UpdateSAMLProvider, CreateOpenIDConnectProvider, CreateAccountAssignment, CreateFunction20150331, UpdateFunctionCode20150331v2, AddPermission20150331v2, ImportKeyPair, ModifyInstanceAttribute, StopLogging, DeleteTrail, PutEventSelectors, DeleteDetector`.

Splunk

```
index=aws sourcetype=aws:cloudtrail errorCode=success OR NOT errorCode=*
  eventName IN (CreateUser, CreateAccessKey, CreateLoginProfile, UpdateLoginProfile, AttachUserPolicy, PutUserPolicy, AddUserToGroup, CreateRole, UpdateAssumeRolePolicy, AttachRolePolicy, PutRolePolicy, CreatePolicyVersion, SetDefaultPolicyVersion, CreateSAMLProvider, UpdateSAMLProvider, CreateOpenIDConnectProvider, CreateAccountAssignment, CreateFunction20150331, UpdateFunctionCode20150331v2, AddPermission20150331v2, ImportKeyPair, ModifyInstanceAttribute, StopLogging, DeleteTrail, PutEventSelectors, DeleteDetector)
| eval actor=coalesce('userIdentity.arn', 'userIdentity.principalId')
| stats count min(_time) as first_seen values(sourceIPAddress) as src_ips values(userAgent) as agents values(recipientAccountId) as accounts by actor eventName
| eventstats dc(eventName) as distinct_actions by actor
| convert ctime(first_seen)
| sort - distinct_actions
```

CrowdStrike (NG-SIEM)

```
#Vendor="aws" event.action=*
| in(field="event.action", values=["CreateUser","CreateAccessKey","CreateLoginProfile","UpdateLoginProfile","AttachUserPolicy","PutUserPolicy","AddUserToGroup","CreateRole","UpdateAssumeRolePolicy","AttachRolePolicy","PutRolePolicy","CreatePolicyVersion","SetDefaultPolicyVersion","CreateSAMLProvider","UpdateSAMLProvider","CreateOpenIDConnectProvider","CreateAccountAssignment","CreateFunction20150331","UpdateFunctionCode20150331v2","AddPermission20150331v2","ImportKeyPair","ModifyInstanceAttribute","StopLogging","DeleteTrail","PutEventSelectors","DeleteDetector"])
| groupBy([user.name, event.action], function=[count(), min(@timestamp, as=FirstSeen), collect([source.ip, user_agent.original], limit=10)])
| sort(FirstSeen, order=desc)
```

KQL

```
let persistEvents = dynamic(["CreateUser","CreateAccessKey","CreateLoginProfile","UpdateLoginProfile","AttachUserPolicy","PutUserPolicy","AddUserToGroup","CreateRole","UpdateAssumeRolePolicy","AttachRolePolicy","PutRolePolicy","CreatePolicyVersion","SetDefaultPolicyVersion","CreateSAMLProvider","UpdateSAMLProvider","CreateOpenIDConnectProvider","CreateAccountAssignment","CreateFunction20150331","UpdateFunctionCode20150331v2","AddPermission20150331v2","ImportKeyPair","ModifyInstanceAttribute","StopLogging","DeleteTrail","PutEventSelectors","DeleteDetector"]);
let baseline = AWSCloudTrail | where TimeGenerated between (ago(60d) .. ago(7d)) and EventName in (persistEvents) | distinct UserIdentityArn, EventName;
AWSCloudTrail
| where TimeGenerated > ago(7d) and EventName in (persistEvents) and isempty(ErrorCode)
| join kind=leftanti baseline on UserIdentityArn, EventName
| summarize Count = count(), FirstSeen = min(TimeGenerated), SrcIPs = make_set(SourceIpAddress, 10), Agents = make_set(UserAgent, 5), Accounts = make_set(RecipientAccountId)
    by UserIdentityArn, UserIdentityType, EventName
| order by FirstSeen desc
```

Elastic (ES|QL)

```
FROM logs-aws.cloudtrail-*
| WHERE event.outcome == "success" AND event.action IN ("CreateUser","CreateAccessKey","CreateLoginProfile","UpdateLoginProfile","AttachUserPolicy","PutUserPolicy","AddUserToGroup","CreateRole","UpdateAssumeRolePolicy","AttachRolePolicy","PutRolePolicy","CreatePolicyVersion","SetDefaultPolicyVersion","CreateSAMLProvider","UpdateSAMLProvider","CreateOpenIDConnectProvider","CreateAccountAssignment","CreateFunction20150331","UpdateFunctionCode20150331v2","AddPermission20150331v2","ImportKeyPair","ModifyInstanceAttribute","StopLogging","DeleteTrail","PutEventSelectors","DeleteDetector")
| STATS c = COUNT(*), first_seen = MIN(@timestamp), src_ips = VALUES(source.ip), agents = VALUES(user_agent.original)
    BY aws.cloudtrail.user_identity.arn, event.action
| SORT first_seen DESC
```

**Query 4B — high-signal patterns: credentials minted for another user, external trust, new IdPs**

Splunk

```
index=aws sourcetype=aws:cloudtrail eventName IN (CreateAccessKey, CreateLoginProfile, UpdateLoginProfile, UpdateAssumeRolePolicy, CreateRole, CreateSAMLProvider, CreateOpenIDConnectProvider)
| eval actor_user=mvindex(split('userIdentity.arn',"/"),-1), target_user='requestParameters.userName'
| eval cross_user=if(isnotnull(target_user) AND target_user!=actor_user,1,0)
| rex field=requestParameters.policyDocument "arn:aws:iam::(?<trusted_acct>\d{12})"
| eval external_trust=if(isnotnull(trusted_acct) AND trusted_acct!=recipientAccountId,1,0)
| where cross_user=1 OR external_trust=1 OR eventName IN ("CreateSAMLProvider","CreateOpenIDConnectProvider")
| table _time recipientAccountId userIdentity.arn eventName target_user trusted_acct sourceIPAddress userAgent
```

CrowdStrike (NG-SIEM)

```
#Vendor="aws"
| in(field="event.action", values=["CreateAccessKey","CreateLoginProfile","UpdateLoginProfile","UpdateAssumeRolePolicy","CreateRole","CreateSAMLProvider","CreateOpenIDConnectProvider"])
| ActorUser := splitString(field="Vendor.userIdentity.arn", by="/", index=-1)
| TargetUser := Vendor.requestParameters.userName
| regex("arn:aws:iam::(?<TrustedAcct>\d{12})", field=Vendor.requestParameters.policyDocument, strict=false)
| case { TargetUser=* | test(TargetUser != ActorUser) | Reason := "cross-user credential";
         TrustedAcct=* | test(TrustedAcct != Vendor.recipientAccountId) | Reason := "external trust";
         event.action=/Provider$/ | Reason := "new identity provider";
         * | Reason := "" }
| Reason != ""
| table([@timestamp, Vendor.recipientAccountId, Vendor.userIdentity.arn, event.action, TargetUser, TrustedAcct, source.ip, Reason])
```

KQL

```
AWSCloudTrail
| where TimeGenerated > ago(30d) and isempty(ErrorCode)
| where EventName in ("CreateAccessKey","CreateLoginProfile","UpdateLoginProfile","UpdateAssumeRolePolicy","CreateRole","CreateSAMLProvider","CreateOpenIDConnectProvider")
| extend Req = parse_json(RequestParameters)
| extend ActorUser = tostring(split(UserIdentityArn, "/")[-1]), TargetUser = tostring(Req.userName)
| extend TrustedAcct = extract(@"arn:aws:iam::(\d{12})", 1, tostring(Req.policyDocument))
| extend Reason = case(isnotempty(TargetUser) and TargetUser != ActorUser, "cross-user credential",
                       isnotempty(TrustedAcct) and TrustedAcct != RecipientAccountId, "external trust",
                       EventName endswith "Provider", "new identity provider", "")
| where isnotempty(Reason)
| project TimeGenerated, RecipientAccountId, UserIdentityArn, EventName, TargetUser, TrustedAcct, SourceIpAddress, UserAgent, Reason
```

Elastic (ES|QL)

```
FROM logs-aws.cloudtrail-*
| WHERE event.outcome == "success" AND event.action IN ("CreateAccessKey","CreateLoginProfile","UpdateLoginProfile","UpdateAssumeRolePolicy","CreateRole","CreateSAMLProvider","CreateOpenIDConnectProvider")
| DISSECT aws.cloudtrail.request_parameters "%{}userName=%{target_user},%{}"
| GROK aws.cloudtrail.request_parameters "arn:aws:iam::%{INT:trusted_acct}"
| EVAL actor_user = aws.cloudtrail.user_identity.arn
| EVAL reason = CASE(target_user IS NOT NULL AND NOT ENDS_WITH(actor_user, target_user), "cross-user credential",
                     trusted_acct IS NOT NULL AND trusted_acct != cloud.account.id, "external trust",
                     ENDS_WITH(event.action, "Provider"), "new identity provider", null)
| WHERE reason IS NOT NULL
| KEEP @timestamp, cloud.account.id, actor_user, event.action, target_user, trusted_acct, source.ip, reason
```

**Common false positives:** Terraform/CloudFormation pipelines (filter by CI role ARN and `userAgent` containing `terraform` or `cloudformation.amazonaws.com`), break-glass procedures, Identity Center provisioning. Cross-account trust to your own org accounts is expected; maintain an allowlist of org account IDs.

---

[← Collection index](README.md) · [Repository home](../README.md)
