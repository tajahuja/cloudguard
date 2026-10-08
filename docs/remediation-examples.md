# Safe mock configuration examples

These are suggested changes to copied local fixture files, not commands that modify AWS.
Validate intended workload access, ownership and dependencies before any real change.

## Console IAM user

Change `properties.mfa_enabled` to `true` for a console-capable user. Review
`managed_policies` and attached `policy_ids` separately: enabling MFA does not remove
administrative authorization or protect every long-lived API credential.
Prefer scoped temporary roles and federation for a future real deployment.

## Public storage

```json
{"block_public_access": true, "public_acl": false, "anonymous_read": false,
 "anonymous_write": false, "policy_public": false}
```

These fields belong under the bucket's properties. They represent simplified effective
guardrails. Real S3 has multiple Block Public Access settings and policy scopes.
Verify encryption of stored objects independently; encryption does not undo public grants.

## Administrative network access

```json
{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "192.0.2.5/32"}
```

This documentation address illustrates a restricted approved source. It is not a real
administrative endpoint. A real environment could instead use authorized session-based access.
Check both IPv4 and IPv6 rules; restrictive IPv4 rules do not cancel unrestricted IPv6 ingress.

## Database protections

```json
{"publicly_accessible": false, "internet_route": false, "encrypted": true,
 "backups_enabled": true, "deletion_protection": true, "logging_enabled": true}
```

These are conceptual target fields, not a complete resource definition. Also review
referenced security-group rules. A real encryption change may require a supported migration,
backup validation and application cutover rather than flipping a JSON boolean.

## Verify the learning exercise

Save a copy of the startup environment under a new name, change one control, scan it, and compare
the rule IDs. Explain why related findings can remain. Test intended access and recovery with
approved methods before claiming a real issue is resolved. Preserve original fixtures for tests.
