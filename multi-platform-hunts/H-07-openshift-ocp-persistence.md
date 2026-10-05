# H-07 — OpenShift (OCP) persistence

**Hypothesis:** An attacker who obtained a kubeconfig, service-account token or OpenShift OAuth token has established cluster persistence by binding themselves or a service account to `cluster-admin`, loosening Security Context Constraints, deploying privileged DaemonSets/CronJobs in system namespaces, registering admission webhooks, or adding an OAuth identity provider they control.

**ATT&CK:** T1098.003 Additional Cloud Roles (RBAC bindings), T1053.007 Container Orchestration Job, T1610 Deploy Container, T1611 Escape to Host, T1136 Create Account (htpasswd/IdP), T1528 / T1552.007 Container API token theft, T1546 (mutating admission webhooks).

**Data sources**

| Source | Notes |
| --- | --- |
| `kube-apiserver`, `openshift-apiserver`, `oauth-apiserver` audit logs | Set audit policy profile to `WriteRequestBodies` (or `AllRequestBodies`) so `requestObject` is captured. Forward with `ClusterLogForwarder` (type `audit`) to Splunk HEC, Sentinel (Logs Ingestion API → custom table, shown here as `OCPAudit_CL`), Elastic (`logs-kubernetes.audit_logs-*`) or CrowdStrike NG-SIEM (HEC-compatible connector, JSON parser) |
| Node logs (auditd/EDR on RHCOS nodes) | Container escapes surface as host process activity — pair with Hunt 3 |
| CrowdStrike Falcon Cloud Security (KAC / container sensor) | Runtime detections for privileged containers and drift |

Raw audit fields used: `verb`, `objectRef.resource`, `objectRef.namespace`, `objectRef.name`, `user.username`, `sourceIPs`, `userAgent`, `requestObject`, `responseStatus.code`. Elastic prefixes these with `kubernetes.audit.`.

**Steps**

1. Run 7A for RBAC, SCC, webhook, OAuth and identity changes; anything granting `cluster-admin`, `admin` on `openshift-*`/`kube-system`, or the `privileged`/`anyuid` SCC is high-signal.
2. Run 7B for new privileged workloads (privileged, hostPID, hostNetwork, hostPath `/`) and DaemonSets/CronJobs created outside your GitOps controller (Argo CD / OpenShift GitOps service account).
3. Run 7C for `pods/exec`, `serviceaccounts/token` creation and API calls from source IPs outside the cluster/bastion ranges.
4. Map each lead to the human or token behind it (`user.username`, `impersonatedUser`), then check the OAuth server logs for the token's origin.
5. Confirm against change records; for malicious hits, delete the bindings/workloads, rotate SA tokens and the kubeadmin secret (or remove it), and review node-level activity.

**Query 7A — RBAC, SCC, admission webhook and IdP changes**

Splunk

```
index=openshift sourcetype IN (openshift:audit, kube:apiserver:audit) verb IN (create, update, patch)
  objectRef.resource IN (clusterrolebindings, rolebindings, clusterroles, securitycontextconstraints, mutatingwebhookconfigurations, validatingwebhookconfigurations, oauths, identities, users, groups)
  NOT user.username IN ("system:serviceaccount:openshift-gitops:*", "system:serviceaccount:openshift-*-operator:*")
| eval grants_admin=if(match(_raw,"cluster-admin|\"privileged\"|\"anyuid\"|\"system:masters\""),1,0)
| stats count min(_time) as first_seen values(objectRef.name) as objects values(sourceIPs{}) as src by user.username objectRef.resource verb grants_admin
| convert ctime(first_seen)
| sort - grants_admin first_seen
```

CrowdStrike (NG-SIEM / LogScale, JSON-parsed audit)

```
in(field="verb", values=["create","update","patch"])
| in(field="objectRef.resource", values=["clusterrolebindings","rolebindings","clusterroles","securitycontextconstraints","mutatingwebhookconfigurations","validatingwebhookconfigurations","oauths","identities","users","groups"])
| user.username!=/^system:serviceaccount:(openshift-gitops|openshift-.*-operator):/
| case { @rawstring=/cluster-admin|"privileged"|"anyuid"|system:masters/ | GrantsAdmin := 1; * | GrantsAdmin := 0 }
| groupBy([user.username, objectRef.resource, verb, GrantsAdmin], function=[count(), min(@timestamp, as=FirstSeen), collect([objectRef.name, sourceIPs[0]], limit=10)])
| sort(GrantsAdmin, order=desc)
```

KQL (custom table `OCPAudit_CL`; adjust column names to your DCR)

```
OCPAudit_CL
| where TimeGenerated > ago(30d) and verb in ("create","update","patch")
| extend Resource = tostring(objectRef.resource), Name = tostring(objectRef.name), Ns = tostring(objectRef.namespace), User = tostring(user.username)
| where Resource in ("clusterrolebindings","rolebindings","clusterroles","securitycontextconstraints","mutatingwebhookconfigurations","validatingwebhookconfigurations","oauths","identities","users","groups")
| where User !startswith "system:serviceaccount:openshift-gitops:" and User !matches regex @"^system:serviceaccount:openshift-.*-operator:"
| extend GrantsAdmin = tostring(requestObject) has_any ("cluster-admin","\"privileged\"","\"anyuid\"","system:masters")
| summarize Count = count(), FirstSeen = min(TimeGenerated), Objects = make_set(Name, 20), SrcIPs = make_set(tostring(sourceIPs[0]), 10) by User, Resource, verb, GrantsAdmin
| order by GrantsAdmin desc, FirstSeen desc
```

Elastic (ES|QL)

```
FROM logs-kubernetes.audit_logs-*
| WHERE kubernetes.audit.verb IN ("create","update","patch")
| WHERE kubernetes.audit.objectRef.resource IN ("clusterrolebindings","rolebindings","clusterroles","securitycontextconstraints","mutatingwebhookconfigurations","validatingwebhookconfigurations","oauths","identities","users","groups")
| WHERE NOT kubernetes.audit.user.username RLIKE """system:serviceaccount:(openshift-gitops|openshift-.*-operator):.*"""
| EVAL grants_admin = event.original RLIKE """.*(cluster-admin|"privileged"|"anyuid"|system:masters).*"""
| STATS c = COUNT(*), first_seen = MIN(@timestamp), objects = VALUES(kubernetes.audit.objectRef.name) BY kubernetes.audit.user.username, kubernetes.audit.objectRef.resource, kubernetes.audit.verb, grants_admin
| SORT grants_admin DESC, first_seen DESC
```

**Query 7B — privileged or host-mounted workloads, and DaemonSets/CronJobs created outside GitOps**

Splunk

```
index=openshift sourcetype IN (openshift:audit, kube:apiserver:audit) verb=create objectRef.resource IN (pods, deployments, daemonsets, cronjobs, jobs, statefulsets)
  NOT user.username IN ("system:serviceaccount:openshift-gitops:*", "system:serviceaccount:kube-system:*")
| eval privileged=if(match(_raw,"\"privileged\":true|\"hostPID\":true|\"hostNetwork\":true|\"hostIPC\":true|\"hostPath\":\{\"path\":\"/\""),1,0)
| eval sys_ns=if(match('objectRef.namespace',"^(kube-system|openshift-.*|default)$"),1,0)
| where privileged=1 OR (sys_ns=1 AND 'objectRef.resource' IN ("daemonsets","cronjobs"))
| table _time user.username objectRef.namespace objectRef.resource objectRef.name privileged sourceIPs{}
```

CrowdStrike

```
verb=create
| in(field="objectRef.resource", values=["pods","deployments","daemonsets","cronjobs","jobs","statefulsets"])
| user.username!=/^system:serviceaccount:(openshift-gitops|kube-system):/
| case { @rawstring=/"privileged":true|"hostPID":true|"hostNetwork":true|"hostIPC":true|"hostPath":\{"path":"\/"/ | Privileged := 1; * | Privileged := 0 }
| SysNs := if(objectRef.namespace=/^(kube-system|openshift-.*|default)$/, then=1, else=0)
| Privileged=1 OR (SysNs=1 AND objectRef.resource=/^(daemonsets|cronjobs)$/)
| table([@timestamp, user.username, objectRef.namespace, objectRef.resource, objectRef.name, Privileged])
```

KQL

```
OCPAudit_CL
| where TimeGenerated > ago(30d) and verb == "create"
| extend Resource = tostring(objectRef.resource), Ns = tostring(objectRef.namespace), Name = tostring(objectRef.name), User = tostring(user.username), Body = tostring(requestObject)
| where Resource in ("pods","deployments","daemonsets","cronjobs","jobs","statefulsets")
| where User !startswith "system:serviceaccount:openshift-gitops:" and User !startswith "system:serviceaccount:kube-system:"
| extend Privileged = Body matches regex @"""privileged"":true|""hostPID"":true|""hostNetwork"":true|""hostIPC"":true|""hostPath"":\{""path"":""/"""
| extend SysNs = Ns matches regex @"^(kube-system|openshift-.*|default)$"
| where Privileged or (SysNs and Resource in ("daemonsets","cronjobs"))
| project TimeGenerated, User, Ns, Resource, Name, Privileged
```

Elastic (ES|QL)

```
FROM logs-kubernetes.audit_logs-*
| WHERE kubernetes.audit.verb == "create" AND kubernetes.audit.objectRef.resource IN ("pods","deployments","daemonsets","cronjobs","jobs","statefulsets")
| WHERE NOT kubernetes.audit.user.username RLIKE """system:serviceaccount:(openshift-gitops|kube-system):.*"""
| EVAL privileged = event.original RLIKE """.*("privileged":true|"hostPID":true|"hostNetwork":true|"hostIPC":true|"hostPath":\{"path":"/").*""",
       sys_ns = kubernetes.audit.objectRef.namespace RLIKE """(kube-system|openshift-.*|default)"""
| WHERE privileged OR (sys_ns AND kubernetes.audit.objectRef.resource IN ("daemonsets","cronjobs"))
| KEEP @timestamp, kubernetes.audit.user.username, kubernetes.audit.objectRef.namespace, kubernetes.audit.objectRef.resource, kubernetes.audit.objectRef.name, privileged
```

**Query 7C — exec into pods, SA token minting, and API use from unexpected networks**

Splunk: `index=openshift (objectRef.subresource=exec OR (objectRef.resource=serviceaccounts objectRef.subresource=token verb=create)) | eval src=mvindex('sourceIPs{}',0) | where NOT cidrmatch("10.0.0.0/8",src) AND NOT cidrmatch("172.16.0.0/12",src) | stats count values(objectRef.namespace) as ns values(objectRef.name) as objs by user.username src userAgent`

CrowdStrike: `(objectRef.subresource=exec) OR (objectRef.resource=serviceaccounts objectRef.subresource=token verb=create) | Src := sourceIPs[0] | !cidr(Src, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"]) | groupBy([user.username, Src, userAgent], function=[count(), collect([objectRef.namespace, objectRef.name])])`

KQL: `OCPAudit_CL | where tostring(objectRef.subresource) == "exec" or (tostring(objectRef.resource) == "serviceaccounts" and tostring(objectRef.subresource) == "token" and verb == "create") | extend Src = tostring(sourceIPs[0]) | where not(ipv4_is_private(Src)) | summarize count(), make_set(tostring(objectRef.namespace)) by tostring(user.username), Src, userAgent`

Elastic ES|QL: `FROM logs-kubernetes.audit_logs-* | WHERE kubernetes.audit.objectRef.subresource == "exec" OR (kubernetes.audit.objectRef.resource == "serviceaccounts" AND kubernetes.audit.objectRef.subresource == "token" AND kubernetes.audit.verb == "create") | EVAL src = TO_IP(MV_FIRST(kubernetes.audit.sourceIPs)) | WHERE NOT CIDR_MATCH(src, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16") | STATS c = COUNT(*) BY kubernetes.audit.user.username, src, kubernetes.audit.userAgent`

**Common false positives:** operators reconciling their own RBAC, OpenShift GitOps, monitoring/logging DaemonSets, SRE break-glass access. Allowlist by service-account identity, not by namespace alone.

---

[← Collection index](README.md) · [Repository home](../README.md)
