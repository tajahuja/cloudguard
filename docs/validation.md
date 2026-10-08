# Local validation — 2026-10-08

Validated on Windows with Python 3.12.14 in the project's own `.venv`.

- Installed direct pinned dependencies and generated `requirements-lock.txt` from the tested environment.
- `pip check`: no broken requirements.
- Generated all four deterministic environment files.
- Secure: 10 resources, 0 findings, score 100/100.
- Startup: 10 resources, 20 findings, score 46/100; 11 critical, 8 high, 1 medium.
- Vulnerable: 10 resources, 43 findings, score 22/100; 17 critical, 16 high, 8 medium, 2 low.
- Enterprise: 40 resources, 4 findings, score 98/100.
- **127 pytest cases passed**, including positive and negative tests for all 41 rules.
- Ruff: all checks passed.
- Report tests verified output files, masked values and autoescaped HTML content.
- Real CLI subprocess scans succeeded; malformed/unreadable input exits cleanly with code 2.
- Streamlit AppTest rendered the dashboard, changed findings, filtered severity, handled empty
  filters, and selected secure/enterprise environments without exceptions.
- `python -m scripts.validate_dashboard` launched a real Streamlit child process on 8504,
  verified its health and HTML endpoint, then stopped only that validation child.

One Streamlit/Altair dependency deprecation warning remains; it does not fail rendering/tests.
Upgrade and retest the dependency pair rather than masking an unknown compatibility issue.

The optional boto3 gate was tested with fake clients only: mismatched confirmation prevents SDK
calls; mismatched caller account prevents inventory reads; the allowed fake flow uses only STS
identity and EC2 security-group pagination. No real AWS account was accessed.

The direct VS Code executable was invoked for the project, but its visible workspace could not
be confirmed. The desktop verification helper timed out during initialization. No browser visual
screenshot or confirmed VS Code window is claimed. README screenshot placeholders remain.
Automated dashboard rendering and live HTTP readiness were verified separately.

The validation server is stopped after checks. Start Streamlit yourself in the VS Code terminal
and keep that terminal open to use http://127.0.0.1:8503. A refused connection means no server is
listening there. Tool-isolated servers may be unreachable from your separate browser session.

No GitHub connection or publishing occurred for CloudGuard. Git milestones remain local.
