from cloudguard.rules.base import Rule
from cloudguard.rules.secrets.redaction import secret_paths

def embedded(e,r):
    paths = secret_paths(r.model_dump(mode='json'))
    return {'sensitive_field_paths': paths,'values':'[REDACTED]'} if paths else None

RULES = [Rule('CG-SEC-001','secrets','Sensitive-looking value embedded in configuration','HIGH',
              ('iam_user','iam_role','iam_policy','bucket','security_group','instance','database','audit_log','monitoring'),embedded,
              'Embedded credentials can be copied through configuration, backups or source control.',
              'Remove the value, use an approved secret store and assess rotation requirements if a real value was exposed.',
              'Secret lifecycle management')]
