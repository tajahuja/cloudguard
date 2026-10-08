from cloudguard.config import OLD_KEY_DAYS, INACTIVE_DAYS
from cloudguard.rules.base import Rule

IDENTITIES = ('iam_user', 'iam_role')
POLICY_TYPES = IDENTITIES + ('iam_policy',)

def statements(environment, resource):
    if resource.resource_type == 'iam_policy':
        return resource.properties.statements
    attached = [r.properties.statements for r in environment.resources
                if r.resource_id in resource.properties.policy_ids]
    return resource.properties.inline_statements + [s for group in attached for s in group]

def grants(environment, resource):
    return [s for s in statements(environment, resource) if s.effect == 'Allow' and not s.conditions]

def administrator(environment, resource):
    return ('AdministratorAccess' in resource.properties.managed_policies or
            any('*' in s.actions and '*' in s.resources for s in grants(environment, resource)))

def admin_check(e, r):
    return {'declared_admin_grant': True, 'effective_permissions': 'not simulated'} if administrator(e,r) else None

def missing_mfa(e, r):
    p = r.properties
    return {'console_access': True, 'mfa_enabled': False,
            'declared_admin_grant': administrator(e,r)} if p.console_access and not p.mfa_enabled else None

def wildcard(e, r):
    bad = [s.model_dump() for s in grants(e,r) if any('*' in a for a in s.actions) and '*' in s.resources]
    return {'unrestricted_allow_statements': bad, 'interpretation': 'review candidate; not effective permission proof'} if bad else None

def old_keys(e, r):
    ages = [k.age_days for k in r.properties.access_keys if k.active and k.age_days > OLD_KEY_DAYS]
    return {'active_key_ages_days': ages, 'lab_threshold_days': OLD_KEY_DAYS} if ages else None

def inactive(e, r):
    return {'last_used_days': r.properties.last_used_days, 'declared_admin_grant': True} if (
        administrator(e,r) and r.properties.last_used_days > INACTIVE_DAYS) else None

def multiple_keys(e, r):
    count = sum(k.active for k in r.properties.access_keys)
    return {'active_key_count': count} if count > 1 else None

def broad_trust(e, r):
    p = r.properties
    return {'trust_principals': p.trust_principals, 'trust_has_conditions': False} if (
        '*' in p.trust_principals and not p.trust_has_conditions) else None

def escalation_candidate(e, r):
    allowed = {a.lower() for s in grants(e,r) if '*' in s.resources for a in s.actions}
    required = {'iam:passrole', 'ec2:runinstances'}
    return {'declared_actions': sorted(required), 'resource_scope': '*',
            'reachability': 'not established'} if required <= allowed else None

def root_keys(e, r):
    return {'root_style_identity': True, 'active_keys': sum(k.active for k in r.properties.access_keys)} if (
        r.properties.is_root and any(k.active for k in r.properties.access_keys)) else None

RULES = [
    Rule('CG-IAM-001','iam','Declared administrative access','HIGH',IDENTITIES,admin_check,
         'Broad grants increase the potential account-level blast radius.',
         'Replace standing admin grants with scoped roles and approved temporary elevation.', 'Least privilege'),
    Rule('CG-IAM-002','iam','Console identity without MFA','HIGH',('iam_user',),missing_mfa,
         'A stolen password could be sufficient for console sign-in when other controls do not intervene.',
         'Require phishing-resistant MFA; prefer federation for human access.', 'Strong authentication'),
    Rule('CG-IAM-003','iam','Wildcard allow statement','HIGH',POLICY_TYPES,wildcard,
         'Unrestricted declared permissions may exceed the intended task.',
         'Scope actions and resources; evaluate denies, boundaries and SCPs before concluding effective access.', 'Least privilege'),
    Rule('CG-IAM-004','iam','Old active access key','MEDIUM',('iam_user',),old_keys,
         'Long-lived credentials extend exposure if copied or forgotten.',
         'Prefer temporary credentials; verify ownership and last use before safely replacing or disabling keys.', 'Credential lifecycle'),
    Rule('CG-IAM-005','iam','Inactive privileged identity','HIGH',IDENTITIES,inactive,
         'Unused powerful identities create unnecessary potential access paths.',
         'Confirm ownership and dependencies, then remove unused access.', 'Access review'),
    Rule('CG-IAM-006','iam','Multiple active access keys','LOW',('iam_user',),multiple_keys,
         'Extra credentials increase management burden; two keys may be legitimate during rotation.',
         'Verify an active rotation plan and remove the superseded key after dependency validation.', 'Credential lifecycle'),
    Rule('CG-IAM-007','iam','Unrestricted role trust','HIGH',('iam_role',),broad_trust,
         'Unconditioned wildcard trust broadens who may be eligible to assume the role.',
         'Restrict trusted principals and add appropriate trust conditions.', 'Trust boundaries'),
    Rule('CG-IAM-008','iam','PassRole and instance-launch combination','HIGH',IDENTITIES,escalation_candidate,
         'This declared combination merits review for possible privilege escalation paths; none are executed.',
         'Scope PassRole to approved roles and workloads; verify trust and other permission guardrails.', 'Separation of duties'),
    Rule('CG-IAM-009','iam','Root-style active access keys','CRITICAL',('iam_user',),root_keys,
         'Root-style credentials have an unusually large potential blast radius.',
         'Remove root access keys through approved procedures; use scoped temporary roles.', 'Protect root credentials')]
