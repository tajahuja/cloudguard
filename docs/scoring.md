# Risk scoring and security posture

## Finding score

The scanner first identifies a misconfiguration, then scores its resource context. Every rule has
a declared base severity; its final finding severity comes from the total score.

| Factor | Points | Meaning |
|---|---:|---|
| Base LOW / MEDIUM / HIGH / CRITICAL | 10 / 30 / 55 / 80 | Rule-specific starting priority |
| Public permission/path | 15 | Bucket effective public grant, group global ingress, routed public instance, or routed public database with global group permission |
| Declared administrative grant | 15 | Identity attached AdministratorAccess or unconditional Allow * / * |
| Confidential data | 10 | Supplied resource classification |
| Encryption absent | 5 | Storage/database encryption or instance volume encryption gap |
| Console MFA absent | 10 | IAM user console access enabled without MFA |
| Visibility gap | 5 | Applicable resource logging/monitoring disabled |
| High criticality | 5 | Supplied asset criticality |

Add each factor once and cap at 100. LOW 0–29; MEDIUM 30–54; HIGH 55–79; CRITICAL 80–100.
The same resource modifiers apply to all its findings, so even a low-base governance issue can
rise with risky context. The explanation is displayed; reviewers should not interpret the score
as a measured probability or independent finding severity certification.

Public security-group permissions are a candidate exposure factor, not proof of reachability.
Ease of misuse and blast radius are approximated by rule base priority, privilege, sensitivity
and exposure. There is no invented exploit-success probability.

Startup administrative MFA finding: 55 + 15 + 10 + 5 = 85 (CRITICAL).
The maximum is 100 even if the raw contributions exceed it.

## Cloud Security Score

1. Initialize every supplied resource's risk to zero.
2. For each resource, take the maximum finding risk among statuses OPEN or ACCEPTED.
3. Compute 100 minus the ceiling of the mean resource risk.

`security_score = 100 - ceil(sum(max_unresolved_risk_per_resource) / resource_count)`

This avoids multiplying the posture penalty when multiple related rules describe one resource.
Two resources with risks 81 and 0 yield 59, not 19. Duplicate findings do not change the score.
Accepted risk remains exposure; a resolved finding no longer contributes. CLI/dashboard snapshots
currently recreate findings as OPEN; status lifecycle persistence is not implemented.

Limitations: risk-free resources can dilute critical cases; incomplete inventory can inflate the
score; resource counts have equal weight; weights are lab judgments. Always present critical/high
counts and the prioritized queue. This is not a certified cloud-security or compliance rating.
