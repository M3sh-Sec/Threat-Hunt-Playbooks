# 0. Before You Start: Splunk Basics & Ground Rules

[← Back to index](../README.md)

### A 5-minute SPL primer (skip if you already know Splunk)
- Every search starts by picking data: `index=email sourcetype=proofpoint` — this says "look in the email index, at Proofpoint data."
- Pipe (`|`) chains commands together, left to right, each one working on the results of the one before it: `index=email ... | stats count by sender_domain | sort -count`
- Common commands you'll use constantly in these playbooks:
  - `stats` — summarize/count/aggregate (e.g., `stats count by src_ip`)
  - `eval` — create a new field or do math/logic (e.g., `eval risk_score=fails*2`)
  - `where` — filter based on a condition (e.g., `where count > 5`)
  - `table` — pick specific columns to display
  - `sort -count` — sort descending (the `-` means descending; no dash = ascending)
  - `timechart` — show a metric over time, useful for spotting spikes
  - `transaction` — group related events together (e.g., all events from one session)
  - `lookup` — join your search results against a reference list (e.g., a list of approved vendor IPs, or your list of executives to watch)
- Time range: set it in the top-right time picker in Splunk's UI, or add it inline: `earliest=-7d latest=now`
- If a search is running slow, it's often because the time range or index is too broad — narrow it, or ask your Splunk admin whether a **tstats-accelerated** version of the search exists (tstats is a faster way to query CIM-normalized data models — mentioned where relevant below).

### Ground rules for every hunt
1. **Get authorization.** Confirm with your manager/SOC lead that you're cleared to query these indexes before you start (especially anything touching HR, customer PII, or executive accounts) and that your Splunk role has access to them.
2. **Never take destructive action yourself** (disabling accounts, isolating hosts, blocking IPs) unless your role explicitly includes IR authority. Your job in a hunt is to **find and document**, then hand off.
3. **Save your searches.** In Splunk, click "Save As > Report" (or "Alert" if you want it to run automatically and notify you) on any query you'll want to reuse — don't retype these every time.
4. **Document as you go.** Use the Documentation Template at the end of this document for every hunt.
5. **Time range matters.** Unless stated otherwise, start with `earliest=-7d`, then expand to `-30d`/`-90d` if you find something interesting or nothing at all.
6. **When in doubt, escalate.** It is always better to flag something that turns out to be benign than to sit on something real.

### Suggested index/sourcetype naming used in the examples below
Adjust these to your real environment before running anything:
| Playbook data need | Example index | Example sourcetype |
|---|---|---|
| Email security | `index=email` | `proofpoint`, `mimecast`, `o365:defender` |
| Identity / sign-in | `index=identity` | `azuread:signin`, `okta`, `o365:management` |
| Endpoint/EDR | `index=endpoint` | `crowdstrike`, `xmldwinlogon`, `wineventlog` |
| Network/proxy/WAF | `index=network` / `index=waf` | `bluecoat`, `zscaler`, `f5:asm` |
| Policy admin / core business app | `index=policyadmin` | `custom:policychange` |
| Call center CRM | `index=callcenter` | `custom:crm` |
| API gateway | `index=api` | `apigee`, `kong`, `aws:apigateway` |

---

