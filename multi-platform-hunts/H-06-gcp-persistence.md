# H-06 — GCP persistence

**Hypothesis:** An adversary with a compromised Google identity or service-account key has established persistence by minting new service-account keys, granting IAM roles to attacker-controlled principals (external Gmail/other-domain accounts or new service accounts), injecting SSH keys or startup scripts through instance/project metadata, adding workload-identity federation providers, or deploying Cloud Functions/Cloud Run/Scheduler jobs.

**ATT&CK:** T1098.001 Additional Cloud Credentials, T1098.003 Additional Cloud Roles, T1098.004 SSH Authorized Keys, T1136.003 Cloud Account, T1484.002 Trust Modification, T1525 Implant Internal Image, T1562.008 Disable Cloud Logs.

**Data sources**

| Source | Notes |
| --- | --- |
| Cloud Audit Logs — Admin Activity (always on) | Org-level aggregated sink to Pub/Sub → Splunk (`google:gcp:pubsub:message`), Sentinel `GCPAuditLogs`, Elastic `logs-gcp.audit-*`, CrowdStrike NG-SIEM GCP connector |
| Cloud Audit Logs — Data Access for IAM (`iam.googleapis.com`, `iamcredentials.googleapis.com`) | Must be enabled; needed to see `GenerateAccessToken` / `SignBlob` impersonation |
| Security Command Center | Event Threat Detection findings (persistence: IAM anomalous grant, new SA key) |

Field mapping: Splunk `data.protoPayload.methodName` / `...authenticationInfo.principalEmail` / `...requestMetadata.callerIp`; Sentinel `MethodName` / `PrincipalEmail` / `CallerIp`; Elastic `event.action` / `client.user.email` / `source.ip`.

**Steps**

1. Run 6A for persistence-related method calls; stack by principal and method and flag first-time combinations.
2. Run 6B to inspect `SetIamPolicy` deltas: members outside your Google Workspace/Cloud Identity domains, `allUsers`/`allAuthenticatedUsers`, or grants of `roles/owner`, `roles/editor`, `roles/iam.serviceAccountTokenCreator`, `roles/iam.serviceAccountKeyAdmin`, `roles/iam.workloadIdentityPoolAdmin`.
3. Run 6C for metadata-based persistence (`ssh-keys`, `startup-script`, `startup-script-url`) and OS Login key imports.
4. For each new SA key, confirm a human or pipeline requested it; check where the key was first used (`authenticationInfo.serviceAccountKeyName` in later calls) and from which IPs.
5. Check for logging tampering in the same window (`DeleteSink`, `UpdateSink`, `google.logging.v2.ConfigServiceV2.UpdateCmekSettings`).

**Query 6A — GCP persistence method calls**

Methods: `google.iam.admin.v1.CreateServiceAccount, google.iam.admin.v1.CreateServiceAccountKey, google.iam.admin.v1.UploadServiceAccountKey, SetIamPolicy, google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPoolProvider, v1.compute.instances.setMetadata, v1.compute.projects.setCommonInstanceMetadata, google.cloud.oslogin.v1.OsLoginService.ImportSshPublicKey, google.cloud.functions.v1.CloudFunctionsService.CreateFunction, google.cloud.functions.v2.FunctionService.CreateFunction, google.cloud.run.v1.Services.CreateService, google.cloud.scheduler.v1.CloudScheduler.CreateJob, google.logging.v2.ConfigServiceV2.DeleteSink, google.logging.v2.ConfigServiceV2.UpdateSink`.

Splunk

```
index=gcp sourcetype=google:gcp:pubsub:message
| rename data.protoPayload.methodName as method, data.protoPayload.authenticationInfo.principalEmail as principal, data.protoPayload.requestMetadata.callerIp as src_ip, data.protoPayload.resourceName as resource
| regex method="(CreateServiceAccount|CreateServiceAccountKey|UploadServiceAccountKey|SetIamPolicy|CreateWorkloadIdentityPoolProvider|instances\.setMetadata|setCommonInstanceMetadata|ImportSshPublicKey|CreateFunction|Services\.CreateService|CloudScheduler\.CreateJob|DeleteSink|UpdateSink)$"
| stats count min(_time) as first_seen values(src_ip) as src_ips values(resource) as resources by principal method
| convert ctime(first_seen)
| sort first_seen desc
```

CrowdStrike (NG-SIEM)

```
#Vendor="google" #event.module=/gcp|cloud_audit/i
| event.action=/(CreateServiceAccount|CreateServiceAccountKey|UploadServiceAccountKey|SetIamPolicy|CreateWorkloadIdentityPoolProvider|instances\.setMetadata|setCommonInstanceMetadata|ImportSshPublicKey|CreateFunction|Services\.CreateService|CloudScheduler\.CreateJob|DeleteSink|UpdateSink)$/
| groupBy([user.email, event.action], function=[count(), min(@timestamp, as=FirstSeen), collect([source.ip], limit=10)])
| sort(FirstSeen, order=desc)
```

KQL

```
let baseline = GCPAuditLogs | where TimeGenerated between (ago(60d) .. ago(7d)) | distinct PrincipalEmail, MethodName;
GCPAuditLogs
| where TimeGenerated > ago(7d)
| where MethodName matches regex @"(CreateServiceAccount|CreateServiceAccountKey|UploadServiceAccountKey|SetIamPolicy|CreateWorkloadIdentityPoolProvider|instances\.setMetadata|setCommonInstanceMetadata|ImportSshPublicKey|CreateFunction|Services\.CreateService|CloudScheduler\.CreateJob|DeleteSink|UpdateSink)$"
| join kind=leftanti baseline on PrincipalEmail, MethodName
| summarize Count = count(), FirstSeen = min(TimeGenerated), IPs = make_set(CallerIp, 10), Projects = make_set(ProjectId, 10) by PrincipalEmail, MethodName
| order by FirstSeen desc
```

Elastic (ES|QL)

```
FROM logs-gcp.audit-*
| WHERE event.outcome == "success" OR event.outcome IS NULL
| WHERE event.action RLIKE """.*(CreateServiceAccount|CreateServiceAccountKey|UploadServiceAccountKey|SetIamPolicy|CreateWorkloadIdentityPoolProvider|instances\.setMetadata|setCommonInstanceMetadata|ImportSshPublicKey|CreateFunction|Services\.CreateService|CloudScheduler\.CreateJob|DeleteSink|UpdateSink)"""
| STATS c = COUNT(*), first_seen = MIN(@timestamp), ips = VALUES(source.ip) BY client.user.email, event.action
| SORT first_seen DESC
```

**Query 6B — IAM grants to external principals or high-privilege roles**

Splunk

```
index=gcp sourcetype=google:gcp:pubsub:message data.protoPayload.methodName="*SetIamPolicy"
| spath path=data.protoPayload.serviceData.policyDelta.bindingDeltas{} output=deltas
| mvexpand deltas
| spath input=deltas
| where action="ADD"
| eval external=if(NOT match(member,"@(yourcompany\.com|.*\.iam\.gserviceaccount\.com)$"),1,0)
| eval priv=if(match(role,"roles/(owner|editor|iam\.serviceAccountTokenCreator|iam\.serviceAccountKeyAdmin|iam\.workloadIdentityPoolAdmin|resourcemanager\.organizationAdmin)"),1,0)
| where external=1 OR priv=1 OR match(member,"allUsers|allAuthenticatedUsers")
| table _time data.protoPayload.authenticationInfo.principalEmail data.protoPayload.resourceName role member external priv
```

CrowdStrike (NG-SIEM)

```
#Vendor="google" event.action=/SetIamPolicy$/
| split(Vendor.protoPayload.serviceData.policyDelta.bindingDeltas)
| Vendor.protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD"
| Member := Vendor.protoPayload.serviceData.policyDelta.bindingDeltas.member
| Role := Vendor.protoPayload.serviceData.policyDelta.bindingDeltas.role
| Member!=/@(yourcompany\.com|.*\.iam\.gserviceaccount\.com)$/ OR Role=/roles\/(owner|editor|iam\.serviceAccountTokenCreator|iam\.serviceAccountKeyAdmin|iam\.workloadIdentityPoolAdmin)/
| table([@timestamp, user.email, Vendor.protoPayload.resourceName, Role, Member])
```

KQL

```
GCPAuditLogs
| where TimeGenerated > ago(30d) and MethodName endswith "SetIamPolicy"
| extend Deltas = parse_json(ServiceData).policyDelta.bindingDeltas
| mv-expand Delta = Deltas
| extend Action = tostring(Delta.action), Role = tostring(Delta.role), Member = tostring(Delta.member)
| where Action == "ADD"
| extend External = Member !matches regex @"@(yourcompany\.com|.*\.iam\.gserviceaccount\.com)$",
         Privileged = Role matches regex @"roles/(owner|editor|iam\.serviceAccountTokenCreator|iam\.serviceAccountKeyAdmin|iam\.workloadIdentityPoolAdmin|resourcemanager\.organizationAdmin)"
| where External or Privileged or Member has_any ("allUsers","allAuthenticatedUsers")
| project TimeGenerated, PrincipalEmail, ProjectId, Role, Member, External, Privileged, CallerIp
```

Elastic (ES|QL)

```
FROM logs-gcp.audit-*
| WHERE ENDS_WITH(event.action, "SetIamPolicy")
| EVAL deltas = gcp.audit.service_data.policy_delta.binding_deltas
| MV_EXPAND deltas
| WHERE deltas LIKE "*ADD*"
| WHERE NOT deltas RLIKE """.*@(yourcompany\.com|[a-z0-9-]+\.iam\.gserviceaccount\.com).*"""
   OR deltas RLIKE """.*roles/(owner|editor|iam\.serviceAccountTokenCreator|iam\.serviceAccountKeyAdmin|iam\.workloadIdentityPoolAdmin).*"""
   OR deltas RLIKE """.*(allUsers|allAuthenticatedUsers).*"""
| KEEP @timestamp, client.user.email, gcp.audit.resource_name, deltas, source.ip
```

(If your Elastic GCP integration stores binding deltas as a flattened object rather than keyword strings, run this as KQL in Discover: `event.action:*SetIamPolicy and gcp.audit.service_data.policy_delta.binding_deltas.action:ADD`.)

**Query 6C — SSH keys and startup scripts injected via metadata**

Splunk: `index=gcp data.protoPayload.methodName IN ("v1.compute.instances.setMetadata","v1.compute.projects.setCommonInstanceMetadata","google.cloud.oslogin.v1.OsLoginService.ImportSshPublicKey") | search "ssh-keys" OR "startup-script" OR ImportSshPublicKey | table _time data.protoPayload.authenticationInfo.principalEmail data.protoPayload.resourceName data.protoPayload.requestMetadata.callerIp`

CrowdStrike: `#Vendor="google" event.action=/(setMetadata|setCommonInstanceMetadata|ImportSshPublicKey)$/ | @rawstring=/ssh-keys|startup-script|ImportSshPublicKey/ | table([@timestamp, user.email, Vendor.protoPayload.resourceName, source.ip])`

KQL: `GCPAuditLogs | where MethodName has_any ("setMetadata","setCommonInstanceMetadata","ImportSshPublicKey") | where tostring(Request) has_any ("ssh-keys","startup-script") or MethodName has "ImportSshPublicKey" | project TimeGenerated, PrincipalEmail, ProjectId, MethodName, CallerIp`

Elastic ES|QL: `FROM logs-gcp.audit-* | WHERE event.action RLIKE ".*(setMetadata|setCommonInstanceMetadata|ImportSshPublicKey)" | WHERE event.original LIKE "*ssh-keys*" OR event.original LIKE "*startup-script*" OR event.action LIKE "*ImportSshPublicKey" | KEEP @timestamp, client.user.email, gcp.audit.resource_name, source.ip`

**Common false positives:** Terraform service accounts, GKE node-pool provisioning (writes metadata), `gcloud compute ssh` (adds per-user keys to metadata when OS Login is off). Replace `yourcompany\.com` with your verified domains.

---

[← Collection index](README.md) · [Repository home](../README.md)
