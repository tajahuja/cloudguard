# Learning guide: understand before listing it on your resume

| Component | What / why | CloudGuard implementation | Real-world equivalent | Interview memory cue |
|---|---|---|---|---|
| Cloud inventory | A list of assets and settings; missing assets cannot be assessed | Four JSON inventories and validated resource IDs | Cloud asset inventory/configuration export | Know WHAT exists |
| Ingestion | Read provider data safely | Bounded JSON/YAML loader, no YAML aliases, redaction before output | Export/collector pipeline | Validate before trusting |
| Normalization | One stable vocabulary for rules | Typed properties per resource plus common classification/tags | CSPM/SIEM normalized schema | Same questions, different formats |
| IAM | Who can access what, under which conditions | Users/roles/policies and declared-grant checks | AWS IAM, federation, authorization policies | WHO can do WHAT to WHICH resource |
| Authentication | Prove identity | Console MFA rule applies only to console-capable users | MFA/federation sign-in | Who are you? |
| Authorization | Permit an action | Policy scope and trust checks; no full policy simulator | IAM permission evaluation | What may you do? |
| Least privilege | Grant only required access | Flag admin/wildcard grants and PassRole combination | Scoped roles, permissions boundaries, access reviews | Minimum necessary |
| Temporary credentials | Short-lived access instead of permanent keys | Key age/multiple-key review; recommendation for roles | STS/federated credentials | Expire by design |
| Storage security | Protect object confidentiality/integrity | Public/anonymous grants, encryption, visibility, versioning | S3 policy/access protection and recovery | Private unless justified |
| Network security | Constrain sources and services | IPv4/IPv6 CIDRs, protocols and port ranges | Security groups, firewalls, private routing | Source + port + path |
| Database security | Protect sensitive persistence | Public flag plus referenced group, encryption/recovery/logging | RDS controls and data-tier isolation | Private, encrypted, recoverable |
| Compute hardening | Reduce host data and metadata exposure | Volume encryption, IMDSv2, monitoring | EC2 instance configuration | Protect disk, metadata, visibility |
| Audit visibility | Establish who changed what | Audit/monitoring/retention checks | CloudTrail, centralized log storage | No logs, fewer answers |
| Secret hygiene | Avoid copying credentials with code/config | Sensitive-field/pattern detection and redacted evidence | Secret stores and rotation workflows | Detect without redistributing |
| Risk scoring | Decide remediation order with context | Base plus explicit factors, cap 100 | Analyst triage/risk register | Priority, not probability |
| Posture score | Summarize inventory risk without counting related findings repeatedly | Mean maximum unresolved risk per asset | CSPM posture dashboards | Average can hide a critical outlier |
| Remediation | Explain corrective control and verify success | Steps, principle, settings, urgency and rerun guidance | Change management and retesting | Fix, verify, document |
| Reporting | Translate technical evidence into decisions | Escaped HTML/Markdown and real-result summaries | Consultant assessment reports | Evidence before conclusions |
| Tests | Check behavior and avoid regressions | All rules have positive/negative cases | Rule validation and CI | A safe case should stay safe |

Start by running secure and startup scans. Compare one field that changed, the rule that fired,
its evidence, and the score contributions. Next fix only MFA in a copied startup file: rerun,
observe the MFA finding disappear, and explain why admin-access findings remain.
Do not edit fixtures you need for tests; save your practice copy under another filename.

Critical distinctions: a finding is a risky configuration; an incident is investigated harmful
activity. A global security-group grant does not prove an attached internet-facing listener.
Encryption does not repair anonymous read access. MFA protects sign-in, not every API key use.
An unconditional Allow is not the whole AWS permission decision. A 100 score is not total security.
