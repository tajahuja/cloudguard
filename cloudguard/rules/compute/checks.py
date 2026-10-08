from cloudguard.rules.base import property_rule

RULES = [
    property_rule('CG-CMP-001','compute','Instance volumes unencrypted','HIGH',['instance'],'encrypted_volumes',True,
                  'Attached modeled volumes lack at-rest encryption.',
                  'Migrate to encrypted volumes through a tested snapshot and restore plan.', 'Encryption at rest'),
    property_rule('CG-CMP-002','compute','IMDSv2 not required','MEDIUM',['instance'],'imdsv2_required',True,
                  'Legacy metadata access lacks IMDSv2 session-token requirements.',
                  'Require IMDSv2 after validating application compatibility.', 'Metadata hardening'),
    property_rule('CG-CMP-003','compute','Instance monitoring disabled','MEDIUM',['instance'],'monitoring_enabled',True,
                  'The modeled critical endpoint lacks operational/security visibility.',
                  'Enable approved endpoint/log monitoring and verify ingestion.', 'Endpoint visibility')]
