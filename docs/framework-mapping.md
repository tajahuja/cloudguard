# Framework and guidance mapping

CloudGuard maps findings to descriptive AWS security best-practice concepts, such as least
privilege, private data tiers, encryption at rest, evidence retention and recovery. It does not
claim CIS benchmark compliance, NIST control implementation or OWASP certification.
No unverified numeric control identifiers are assigned.

Authoritative guidance reviewed on 2026-10-08:

- [IAM security best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html): scoped access, MFA, temporary credentials and access reviews.
- [S3 security best practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html): private access, data protection and visibility.
- [S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html): protection at multiple policy scopes.
- [S3 default encryption](https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-encryption-faq.html): new uploads are encrypted by default; legacy storage fixtures are not a modern S3 behavior claim.
- [Security-group rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html): ingress/egress sources, protocols and ports.
- [RDS security](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.html): database security responsibilities and safeguards.
- [CloudTrail security practices](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html): trustworthy audit visibility.
- [EC2 metadata service configuration](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html): metadata-access hardening.
- [Secrets Manager best practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html): secret management rather than embedded credentials.

Exact compliance mapping would require a selected benchmark version, control evidence, exclusions
and assessor verification. The current descriptive mappings are learning cues, not audit assertions.
