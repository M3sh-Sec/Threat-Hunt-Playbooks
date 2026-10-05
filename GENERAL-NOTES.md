# General Program Notes

## Splunk fraud playbooks (FS series)

- New to threat hunting or Splunk? Run playbooks 1, 3, 5, and 9 first. They have the clearest signals and the simplest SPL to practice on.
- Before your first hunt, run `| eventcount summarize=false index=*` and `| fieldsummary` on key sourcetypes to confirm the actual index/sourcetype/field names in your environment. The names in these playbooks are illustrative and will need adjusting.
- Always establish a baseline of "normal" for your specific environment (run any `stats`/`count` query over a known-quiet week first) before judging something as "abnormal."
- Convert every recurring hunt into a saved Splunk **Alert** once you've validated it doesn't produce too many false positives. That's how a manual hunting program grows into continuous detection.
- If your organization has **Splunk Enterprise Security (ES)**, consider migrating the highest-value queries (especially Playbooks 5 and 11) into ES's Risk-Based Alerting framework so multiple weaker signals on the same host/user automatically sum into a single high-confidence notable event.
- Re-run each hunt on a recurring cadence (weekly for playbooks 1-5 and 9-10, monthly for the rest) and immediately after any relevant threat intelligence bulletin (e.g., FS-ISAC alerts for the financial sector).

## Multi-platform hunts (H series)

- Run P1 hunts (H-05, H-08, H-09, H-11, H-13, H-15, H-17) weekly until each is converted into a scheduled detection; see the cadence table in the [appendix](multi-platform-hunts/appendix-cadence-field-mappings-sources.md).
- Validate field names for your parsers before running any query; the appendix lists porting notes for each query language.
- Re-run the identity, SaaS and RMM hunts immediately after any advisory about Scattered Spider, ShinyHunters or ransomware affiliates targeting your sector.
