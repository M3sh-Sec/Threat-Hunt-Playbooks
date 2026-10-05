# H-09 — Identity takeover: vishing, MFA fatigue, AiTM and rogue MFA devices (techniques 1–5)

**Hypothesis:** An attacker has socially engineered our service desk or an employee to reset a password or MFA factor, or has used push bombing or an adversary-in-the-middle phishing kit, and is now signing in as that user from infrastructure we have never seen (residential proxies, VPNs, hosting ASNs) with a newly enrolled MFA device.

**Data sources:** Entra ID `SigninLogs` + `AuditLogs`; Okta System Log (Splunk `OktaIM2:log`, Elastic `logs-okta.system-*`, CrowdStrike NG-SIEM Okta connector, Sentinel `Okta_CL` / `OktaV2_CL`); service-desk ticketing system (ServiceNow) for reset tickets; telephony/IVR logs if available; CrowdStrike Falcon Identity Protection detections.

**Steps**

1. Run 9A for MFA push bombing: 5 or more denied/timed-out pushes for one user within 1 hour, followed by a success.
2. Run 9B for help-desk takeover: an admin-initiated password or factor reset followed within 24 hours by a sign-in from a new IP/ASN or a new factor enrollment. Join to ServiceNow tickets and verify the caller was validated (callback to the number on file, manager approval).
3. Run 9C for session replay (AiTM): the same session ID appearing from two different ASNs or countries within a short window, or Entra risk detections `anomalousToken`, `tokenIssuerAnomaly`, `attackerinTheMiddle`.
4. For every confirmed lead: revoke sessions, reset the factor through a verified process, and pivot the user and IP into Hunts 5, 8, 11 and 13 — Scattered Spider moves to SaaS, RMM tools and new federation within hours.

**Query 9A — MFA push bombing followed by success**

Splunk (Okta + Entra)

```
(index=okta sourcetype=OktaIM2:log eventType IN ("user.mfa.okta_verify.deny_push","system.push.send_factor_verify_push","user.authentication.auth_via_mfa"))
OR (index=azure sourcetype=azure:aad:signin)
| eval user=coalesce('actor.alternateId', userPrincipalName), ip=coalesce('client.ipAddress', ipAddress)
| eval mfa_fail=if(eventType="user.mfa.okta_verify.deny_push" OR (eventType="system.push.send_factor_verify_push" AND 'outcome.result'!="SUCCESS") OR 'status.errorCode' IN (500121, 50074, 50076),1,0)
| eval mfa_ok=if((eventType="user.authentication.auth_via_mfa" AND 'outcome.result'="SUCCESS") OR 'status.errorCode'=0,1,0)
| bin _time span=1h
| stats sum(mfa_fail) as fails sum(mfa_ok) as success values(ip) as ips by user _time
| where fails>=5 AND success>=1
```

CrowdStrike (NG-SIEM)

```
(#Vendor="okta" in(field="event.action", values=["user.mfa.okta_verify.deny_push","system.push.send_factor_verify_push","user.authentication.auth_via_mfa"]))
OR (#Vendor="microsoft" #event.module=/entra|azure/i event.category=authentication)
| case { event.action="user.mfa.okta_verify.deny_push" | Fail := 1;
         event.action="system.push.send_factor_verify_push" event.outcome!="success" | Fail := 1;
         in(field="Vendor.properties.status.errorCode", values=["500121","50074","50076"]) | Fail := 1;
         event.outcome="success" | Ok := 1;
         * | Fail := 0 }
| bucket(span=1h, field=user.name, function=[sum(Fail, as=Fails), sum(Ok, as=Successes), collect([source.ip], limit=10)])
| Fails >= 5 Successes >= 1
```

KQL

```
SigninLogs
| where TimeGenerated > ago(14d)
| summarize Fails = countif(ResultType in ("500121","50074","50076") or tostring(Status.additionalDetails) has "MFA denied"),
            Success = countif(ResultType == "0"),
            IPs = make_set(IPAddress, 10), Countries = make_set(tostring(LocationDetails.countryOrRegion), 5)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where Fails >= 5 and Success >= 1
| order by TimeGenerated desc
```

Elastic (ES|QL, Okta)

```
FROM logs-okta.system-*
| WHERE okta.event_type IN ("user.mfa.okta_verify.deny_push","system.push.send_factor_verify_push","user.authentication.auth_via_mfa")
| EVAL fail = CASE(okta.event_type == "user.mfa.okta_verify.deny_push", 1, okta.event_type == "system.push.send_factor_verify_push" AND okta.outcome.result != "SUCCESS", 1, 0),
       ok = CASE(okta.event_type == "user.authentication.auth_via_mfa" AND okta.outcome.result == "SUCCESS", 1, 0)
| STATS fails = SUM(fail), successes = SUM(ok), ips = VALUES(source.ip) BY okta.actor.alternate_id, hour = DATE_TRUNC(1 hour, @timestamp)
| WHERE fails >= 5 AND successes >= 1
```

**Query 9B — admin/help-desk reset followed by sign-in from a new network or new factor enrollment (Okta)**

Splunk

```
index=okta sourcetype=OktaIM2:log eventType IN ("user.account.reset_password","user.mfa.factor.reset_all","user.mfa.factor.deactivate","user.account.unlock_by_admin")
| eval victim=mvindex('target{}.alternateId',0), reset_time=_time, reset_by='actor.alternateId'
| join type=inner victim [search index=okta sourcetype=OktaIM2:log eventType IN ("user.session.start","user.mfa.factor.activate","device.enrollment.create") outcome.result=SUCCESS | eval victim='actor.alternateId', follow_time=_time, follow_ip='client.ipAddress', follow_asn='securityContext.asOrg', follow_event=eventType | fields victim follow_time follow_ip follow_asn follow_event]
| where follow_time>reset_time AND follow_time<reset_time+86400
| table reset_time reset_by victim follow_event follow_time follow_ip follow_asn
```

CrowdStrike (NG-SIEM `correlate`)

```
correlate(
  reset: { #Vendor="okta" in(field="event.action", values=["user.account.reset_password","user.mfa.factor.reset_all","user.mfa.factor.deactivate"]) | Victim := Vendor.target[0].alternateId },
  follow: { #Vendor="okta" in(field="event.action", values=["user.session.start","user.mfa.factor.activate"]) event.outcome=success | Victim := user.email } include: [source.ip, event.action],
  sequence=true, within=24h, globalConstraints=[Victim])
```

KQL (Okta in Sentinel; Entra version is Query 5A-2)

```
let resets = OktaV2_CL
| where TimeGenerated > ago(30d) and EventOriginalType in ("user.account.reset_password","user.mfa.factor.reset_all","user.mfa.factor.deactivate")
| extend Victim = tostring(TargetUserPrincipalName), ResetBy = ActorUsername, ResetTime = TimeGenerated;
OktaV2_CL
| where TimeGenerated > ago(30d) and EventOriginalType in ("user.session.start","user.mfa.factor.activate") and EventResult == "Success"
| extend Victim = ActorUsername, FollowTime = TimeGenerated
| join kind=inner resets on Victim
| where FollowTime between (ResetTime .. (ResetTime + 24h))
| project ResetTime, ResetBy, Victim, EventOriginalType, FollowTime, SrcIpAddr, SrcGeoCountry
```

Elastic (EQL)

```
sequence with maxspan=24h
  [any where event.dataset == "okta.system" and okta.event_type : ("user.account.reset_password", "user.mfa.factor.reset_all", "user.mfa.factor.deactivate")] by okta.target.alternate_id
  [any where event.dataset == "okta.system" and okta.event_type : ("user.session.start", "user.mfa.factor.activate") and okta.outcome.result == "SUCCESS"] by okta.actor.alternate_id
```

**Query 9C — session token replay from multiple networks (AiTM indicator)**

Splunk: `index=azure sourcetype=azure:aad:signin status.errorCode=0 | iplocation ipAddress | stats dc(ipAddress) as ips dc(Country) as countries values(ipAddress) values(Country) by sessionId userPrincipalName | where countries>1 OR ips>3`

CrowdStrike: `#Vendor="microsoft" event.category=authentication event.outcome=success | ipLocation(source.ip) | groupBy([Vendor.properties.sessionId, user.name], function=[count(source.ip, distinct=true, as=IPs), count(source.ip.country, distinct=true, as=Countries), collect([source.ip, source.ip.country])]) | Countries > 1 OR IPs > 3`

KQL:

```
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d) and ResultType == "0" and isnotempty(SessionId)
| extend Country = tostring(LocationDetails.countryOrRegion), ASN = tostring(AutonomousSystemNumber)
| summarize IPs = dcount(IPAddress), ASNs = dcount(ASN), Countries = make_set(Country), IPList = make_set(IPAddress, 10), Span = max(TimeGenerated) - min(TimeGenerated)
    by SessionId, UserPrincipalName
| where ASNs > 1 and Span < 6h
| join kind=leftouter (AADUserRiskEvents | where RiskEventType in ("anomalousToken","tokenIssuerAnomaly","attackerinTheMiddle") | project UserPrincipalName, RiskEventType) on UserPrincipalName
```

Elastic ES|QL: `FROM logs-azure.signinlogs-* | WHERE event.outcome == "success" | STATS ips = COUNT_DISTINCT(source.ip), asns = COUNT_DISTINCT(source.as.number), countries = VALUES(source.geo.country_iso_code) BY azure.signinlogs.properties.session_id, user.name | WHERE asns > 1`

**Common false positives:** users on mobile networks switching between Wi-Fi and cellular (same session, two ASNs), corporate VPN split tunnels, legitimate self-service resets. Prioritize resets that came through the phone channel and sessions touching residential proxy or hosting ASNs.

---

[← Collection index](README.md) · [Repository home](../README.md)
