# Optional AWS integration: explicit and read-only

Nothing in the local CLI or dashboard reads an AWS profile, retrieves credentials or contacts AWS.
The optional module is invoked separately, after a human explicitly authorizes their own account.
Install `requirements-aws.txt` only when needed. Credential resolution is delegated to boto3's
approved provider chain; never put keys into source files or commit AWS credential files.

The collector requires matching `--expected-account` and `--confirm-live-account` values, plus
an explicit profile, region and output path. It checks STS caller identity first and stops on a
mismatched account. Only then does it paginate EC2 DescribeSecurityGroups. No modifying service
operation exists. The export contains resource/account metadata and should remain private.

The following policy is a narrow starting point for an authorized lab role, not a blanket
administrator or generic SecurityAudit grant:

```json
{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Action":["ec2:DescribeSecurityGroups"],"Resource":"*"}
]}
```

Many EC2 Describe APIs require a wildcard resource scope. Restrict the role's trust, account,
session duration and permitted region according to organization controls. STS GetCallerIdentity
is used for identity verification; consult [its documented permission behavior](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html).
Review the policy with the account owner before use. This is not a recommendation to connect now.

Exports are raw security-group inventory only. They are not accepted by the synthetic Environment
schema and are not a complete assessment. A future adapter must add coverage provenance,
pagination/retry policies, typed normalization and effective policy/context analysis.
Unit tests use fake clients and confirm gating/mismatch behavior. No live AWS validation was performed.
