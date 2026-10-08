# Interview guide — concise answers based on CloudGuard

**What is cloud security?** Protecting cloud identities, configurations, data and workloads under
shared responsibilities. My lab focuses on customer configuration choices, not provider infrastructure.

**What is IAM?** Identity and Access Management describes who may perform which action on which
resource under which conditions. CloudGuard models users, roles and policies and flags broad declared grants.

**Authentication versus authorization?** Authentication proves identity; authorization decides
permitted actions. MFA is an authentication protection; policy scope is authorization.

**Users versus roles?** Users can have long-lived credentials. Roles are assumed to obtain temporary
credentials. My model treats console MFA as a user setting and role trust as a separate boundary.

**What is least privilege?** Grant the smallest access required for the workload. I flag wildcard
and administrative grants, then recommend scoped roles and verified task requirements.

**Why MFA?** It adds a sign-in protection if a password is stolen. I do not claim console MFA alone
protects long-lived API keys. Federation and temporary credentials are preferable where practical.

**What is a security group?** A stateful cloud network permission boundary using sources,
protocols and ports. CloudGuard checks mock ingress/egress and related database group attachments.

**Why can 0.0.0.0/0 be dangerous?** It includes every IPv4 source. For administrative services that
broadens potential access. I also handle ::/0 for IPv6; approved public HTTPS is not automatically flagged as SSH.

**Why public storage risk?** Effective public or anonymous permissions can expose or modify
objects outside intended identities. Encryption at rest does not remove an authorized public read grant.

**Why encryption?** It protects stored data under appropriate key/access controls. CloudGuard
flags modeled gaps, while documenting modern S3's automatic encryption for new uploads.

**What does cloud audit logging do?** Records control-plane activity useful for accountability
and investigation. I check audit availability, coverage, integrity validation and lab retention.

**How does scoring work?** Base 10/30/55/80 plus exposure, privilege, classification and protection
gaps, capped at 100. Every contribution is shown. Posture averages each asset's worst unresolved risk.

**Vulnerability versus misconfiguration?** A vulnerability is a weakness that may include a software
flaw; a misconfiguration is an unsafe setting or access decision. My tool assesses configurations.

**Finding versus incident?** A finding identifies a control gap. An incident involves investigated
harmful activity. My scanner does not observe attacks, confirm compromise or execute response.

**Why do misconfigurations cause breaches?** Excessive trust or public access can make data/services
accessible beyond intention. Real outcomes depend on credentials, paths and other controls.

**How does CloudGuard detect issues?** It validates local JSON/YAML into typed resources, applies
41 category rules, retains evidence, scores context, then generates guidance and reports.

**How could it scale to AWS?** Add authorized paginated collectors and provenance, normalize live
resources, model effective permissions, support multi-account access boundaries and persistent finding state.
The current optional collector only exports account-verified security groups; it is not a full adapter.

**How would you reduce false positives?** Record business intent, ownership, exception expiry and
coverage limits. Treat public websites, key rotation overlaps and unrestricted egress contextually.
Use narrow, evidence-based exceptions rather than disabling broad rule categories.

**What is the most important lesson?** Explain the observation separately from the risk hypothesis.
My network grants and IAM combinations are review candidates, not proof of exploitability.
