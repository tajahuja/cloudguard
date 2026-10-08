# Three-to-five-minute recruiter demonstration

## Before the meeting
Open cloudguard in VS Code. Run the demo, start Streamlit on port 8503 and open its URL.
The default startup contains 10 resources, 20 findings and score 46/100. Keep the HTML report ready.
All data is synthetic and all secret-looking values are invalid placeholders.

## 0:00–0:30 — Explain the problem
“CloudGuard shows how configuration choices can create cloud risk. It assesses mock infrastructure
locally, explains evidence and prioritizes remediation without attacking anything.”
Point to the 41 rules and eight categories in the README architecture diagram.

## 0:30–1:00 — Establish the contrast
Show startup's score and severity counts. Switch to secure: ten resources, zero findings, score 100.
“This means my implemented controls pass on the fixture, not that a real account is perfectly secure.”
Switch back to startup. Show the category and resource-risk charts.

## 1:00–1:45 — Identity evidence
Filter category IAM and select Console identity without MFA. Explain console access, absent MFA,
declared AdministratorAccess, and the 85 score: 55 + 15 + 10 + 5. Read the verification steps.
“A configuration risk is not a confirmed incident. I would validate ownership and permissions.”

## 1:45–2:30 — Data and network context
Clear IAM filter. Select confidential public storage or database findings. Explain that public storage
and missing encryption are distinct controls. Show database public addressing plus its global IPv6
group rule. State that a security-group grant alone does not prove a reachable service.

## 2:30–3:00 — Turn findings into work
Show the sorted queue and report download. Open the HTML assessment: executive summary, affected
assets, masked evidence, risk reasoning, guidance and verification. Point out the secret finding's
redacted field path rather than a copied credential value.

## 3:00–4:00 — Demonstrate remediation and validation
Explain a copied startup fixture with MFA enabled would stop triggering the MFA rule while the
administrative-grant review remains. Show the test command and positive/negative rule cases.
No changes are applied to cloud infrastructure by the tool.

## 4:00–5:00 — Engineering judgment
Show the schema and modular rule registry. Explain the batch/synthetic limits, incomplete IAM
evaluation, posture dilution and optional account-verified read-only collector. Conclude with the
next improvement: a full authorized normalization adapter plus persistent exception management.
