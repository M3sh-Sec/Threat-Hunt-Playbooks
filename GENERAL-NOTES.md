# General Program Notes

[← Back to index](README.md)

- New to threat hunting or Splunk? Run playbooks 1, 3, 5, and 9 first — they have the clearest signals and simplest SPL to practice on.
- Before your first hunt, run `| eventcount summarize=false index=*` and `| fieldsummary` on key sourcetypes to confirm the actual index/sourcetype/field names in your environment — the names in this document are illustrative and will need adjusting.
- Always establish a baseline of "normal" for your specific environment (run any `stats`/`count` query over a known-quiet week first) before judging something as "abnormal."
- Convert every recurring hunt into a saved Splunk **Alert** once you've validated it doesn't produce excessive false positives — this is how a manual hunting program evolves into continuous detection.
- If your organization has **Splunk Enterprise Security (ES)**, consider migrating the highest-value queries (especially Playbooks 5 and 11) into ES's Risk-Based Alerting framework so multiple weaker signals on the same host/user automatically sum into a single high-confidence notable event.
- Re-run each hunt on a recurring cadence (weekly for playbooks 1–5 and 9–10, monthly for the rest) and immediately after any relevant threat intelligence bulletin (e.g., FS-ISAC alerts for the financial sector).
