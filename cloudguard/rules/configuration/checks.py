from cloudguard.rules.base import Rule

TYPES=('iam_user','iam_role','iam_policy','bucket','security_group','instance','database','audit_log','monitoring')
def absent_tag(tag):
    return lambda e,r: {'missing_tag':tag} if not r.tags.get(tag,'').strip() else None

RULES = [
    Rule('CG-CFG-001','configuration','Resource owner tag absent','LOW',TYPES,absent_tag('owner'),
         'Missing ownership delays triage and accountable remediation.',
         'Assign an accountable owner tag and validate it against the inventory.', 'Asset accountability'),
    Rule('CG-CFG-002','configuration','Environment tag absent','LOW',TYPES,absent_tag('environment'),
         'An unlabeled environment makes production/testing context unclear.',
         'Set an accurate environment tag and enforce tagging in deployment checks.', 'Asset classification')]
