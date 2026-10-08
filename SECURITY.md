# Security and ethical boundaries

CloudGuard is a local defensive educational configuration assessor. It does not scan remote hosts,
deploy infrastructure, exercise credentials, exploit services or modify cloud settings. All bundled
environments are fictional; secret values contain FAKE/INVALID placeholders and are not usable.
Public fixture addresses use documentation networks. 0.0.0.0/0 and ::/0 are rule metadata, not targets.

Local analysis is restricted to the synthetic schema. Optional AWS access needs explicit human
authorization for the expected account and matching CLI confirmation. STS verifies the credential
account before the read-only inventory export. No AWS account was accessed during construction.

Use HTTPS-based SDK credential providers/profiles only for an approved future integration. Never
commit .env, keys, AWS credential files, database outputs or virtual environments. Local reports
may contain infrastructure metadata even after redaction; treat any future real export as private.

The loader limits input size, rejects YAML aliases/unsafe tags, validates references and redacts
recognized secret fields/patterns. Redaction is not an exhaustive secret detection guarantee.
Validation/CLI errors omit raw input. HTML report data is autoescaped; CSS/theme markup is static.
Do not paste real credentials into fixtures. If a real credential is exposed, follow the owner's
approved revocation, investigation and replacement workflow; the scanner cannot perform it.

Keep Streamlit bound to 127.0.0.1. There is no public-hosting authentication, authorization,
multi-user isolation or hardened upload service. No remote document/report content is executed.
Inputs are local files; missing assets and unsupported policy semantics remain outside coverage.

Use findings as hypotheses requiring contextual validation. Scoring is educational, not certified
or probabilistic. Reports and JSON are replaceable snapshots, not immutable incident evidence.
Dependencies are reproducible pins, not a guarantee of vulnerability absence; review advisories
and test upgrades before broader use. Contact the repository owner privately for security issues;
no invented contact address is provided.
