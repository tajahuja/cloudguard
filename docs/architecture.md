# Architecture and engineering milestones

## Milestone 1 — Model the cloud without touching the cloud
Four deterministic inventories contain users, roles, policies, buckets, security groups,
instances, databases, audit trails and monitoring. They are mock AWS-style exports, not IaC
deployment files. No secret is real and no address is contacted. The loader accepts JSON and
safe YAML with a size limit; aliases and unsafe tags are rejected. Required settings and typed
relationships prevent silent assumptions when a reference or security field is missing.

## Milestone 2 — Normalize, then detect
Resource translates each type's properties into a specific Pydantic model. Forty-one Rule
definitions live in eight small category modules. A shared engine evaluates applicable rules,
retains evidence, attaches guidance and generates stable resource/rule/account-based IDs.
An inventory resource missing from the supplied file is outside scan coverage.

## Milestone 3 — Context and remediation
Scoring is independent of detection and uses explicit resource factors. The remediation engine
adds urgency, a defensive principle, recommended settings and verification. Nothing applies
changes: owners must validate dependencies and approve remediation in their environment.
The prioritized queue is sorted by score with deterministic ties.

## Milestone 4 — Explain and present
The JSON assessment is a redacted snapshot. Jinja2 autoescaping protects generated HTML from
untrusted resource names/evidence. Reports summarize actual findings rather than canned counts.
Streamlit recomputes the selected local file and supports four filters, finding details and report
downloads. No extra database/API is needed for this small reproducible batch workflow.
Output replacement is atomic per file, not an all-files transactional store.

## Milestone 5 — Safe future integration
The optional SDK collector is separate from the synthetic scanner. Account confirmation must
match the expected account, then STS identity must agree before EC2 inventory calls occur.
All service operations are read-only. Unit tests inject a fake SDK. No live account was accessed.
Only security-group inventory export is implemented; full live normalization/assessment is future work.
