# Rule catalog

41 implemented checks. IDs are project-local, not compliance control numbers.

| ID | Category | Base severity | Title | Applicable types |
|---|---|---|---|---|
| CG-IAM-001 | iam | HIGH | Declared administrative access | iam_user, iam_role |
| CG-IAM-002 | iam | HIGH | Console identity without MFA | iam_user |
| CG-IAM-003 | iam | HIGH | Wildcard allow statement | iam_user, iam_role, iam_policy |
| CG-IAM-004 | iam | MEDIUM | Old active access key | iam_user |
| CG-IAM-005 | iam | HIGH | Inactive privileged identity | iam_user, iam_role |
| CG-IAM-006 | iam | LOW | Multiple active access keys | iam_user |
| CG-IAM-007 | iam | HIGH | Unrestricted role trust | iam_role |
| CG-IAM-008 | iam | HIGH | PassRole and instance-launch combination | iam_user, iam_role |
| CG-IAM-009 | iam | CRITICAL | Root-style active access keys | iam_user |
| CG-STO-001 | storage | HIGH | Storage allows public access | bucket |
| CG-STO-002 | storage | HIGH | Anonymous storage read | bucket |
| CG-STO-003 | storage | CRITICAL | Anonymous storage write | bucket |
| CG-STO-004 | storage | CRITICAL | Sensitive storage exposed publicly | bucket |
| CG-STO-005 | storage | HIGH | Unconditioned public storage policy | bucket |
| CG-STO-006 | storage | MEDIUM | Legacy storage encryption absent | bucket |
| CG-STO-007 | storage | MEDIUM | Storage access visibility absent | bucket |
| CG-STO-008 | storage | LOW | Storage versioning disabled | bucket |
| CG-NET-001 | network | HIGH | Security group permits public SSH | security_group |
| CG-NET-002 | network | HIGH | Security group permits public RDP | security_group |
| CG-NET-003 | network | HIGH | Security group permits public database ports | security_group |
| CG-NET-004 | network | CRITICAL | Unrestricted inbound traffic | security_group |
| CG-NET-005 | network | HIGH | Broad public inbound port range | security_group |
| CG-NET-006 | network | LOW | Unrestricted outbound traffic | security_group |
| CG-DB-001 | database | HIGH | Database public accessibility enabled | database |
| CG-DB-002 | database | CRITICAL | Confidential database has public accessibility | database |
| CG-DB-003 | database | HIGH | Database has globally permitted ingress | database |
| CG-DB-004 | database | HIGH | Database encryption disabled | database |
| CG-DB-005 | database | MEDIUM | Database backups disabled | database |
| CG-DB-006 | database | LOW | Database deletion protection disabled | database |
| CG-DB-007 | database | MEDIUM | Database logging disabled | database |
| CG-LOG-001 | logging | HIGH | Cloud audit logging disabled | audit_log |
| CG-LOG-002 | logging | MEDIUM | Audit trail lacks multi-region coverage | audit_log |
| CG-LOG-003 | logging | LOW | Audit log validation disabled | audit_log |
| CG-LOG-004 | logging | MEDIUM | Log retention below lab baseline | audit_log, monitoring |
| CG-LOG-005 | logging | HIGH | Security monitoring disabled | monitoring |
| CG-CMP-001 | compute | HIGH | Instance volumes unencrypted | instance |
| CG-CMP-002 | compute | MEDIUM | IMDSv2 not required | instance |
| CG-CMP-003 | compute | MEDIUM | Instance monitoring disabled | instance |
| CG-CFG-001 | configuration | LOW | Resource owner tag absent | iam_user, iam_role, iam_policy, bucket, security_group, instance, database, audit_log, monitoring |
| CG-CFG-002 | configuration | LOW | Environment tag absent | iam_user, iam_role, iam_policy, bucket, security_group, instance, database, audit_log, monitoring |
| CG-SEC-001 | secrets | HIGH | Sensitive-looking value embedded in configuration | iam_user, iam_role, iam_policy, bucket, security_group, instance, database, audit_log, monitoring |

Each rule exposes evidence, defensive impact, recommended configuration and verification through the shared finding engine.
Network wide-port threshold (1000-port span), inactive/key age (90 days) and retention (90 days) are lab baselines.
All egress is a review item, not automatically an exploitable defect; broad IAM grants remain declared-permission candidates.
