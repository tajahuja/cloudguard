from cloudguard.rules.base import Rule, property_rule

def effective_public(e, r):
    p = r.properties
    return not p.block_public_access and (p.public_acl or p.policy_public or p.anonymous_read or p.anonymous_write)

def public(e, r):
    p=r.properties
    return {'block_public_access': p.block_public_access, 'public_acl': p.public_acl,
            'policy_public': p.policy_public, 'anonymous_read': p.anonymous_read,
            'anonymous_write': p.anonymous_write} if effective_public(e,r) else None

def anonymous(field):
    return lambda e,r: {field: True, 'block_public_access': False} if (
        not r.properties.block_public_access and getattr(r.properties,field)) else None

def sensitive_public(e,r):
    return {'sensitivity': r.sensitivity, **public(e,r)} if r.sensitivity=='confidential' and effective_public(e,r) else None

def dangerous_policy(e,r):
    p=r.properties
    return {'policy_public': True, 'policy_has_conditions': False, 'block_public_access': False} if (
        not p.block_public_access and p.policy_public and not p.policy_has_conditions) else None

RULES = [
    Rule('CG-STO-001','storage','Storage allows public access','HIGH',('bucket',),public,
         'Public permissions may expose objects beyond intended identities.',
         'Enable Block Public Access unless explicitly approved public distribution is required.', 'Private by default'),
    Rule('CG-STO-002','storage','Anonymous storage read','HIGH',('bucket',),anonymous('anonymous_read'),
         'Unauthenticated readers may obtain data covered by the modeled permission.',
         'Remove anonymous read permissions and verify access with approved policy analysis.', 'Access control'),
    Rule('CG-STO-003','storage','Anonymous storage write','CRITICAL',('bucket',),anonymous('anonymous_write'),
         'Unauthenticated writers may modify or introduce data when the grant is effective.',
         'Remove anonymous write permissions and review object integrity and ownership.', 'Integrity protection'),
    Rule('CG-STO-004','storage','Sensitive storage exposed publicly','CRITICAL',('bucket',),sensitive_public,
         'Public access to confidential data could create a data-disclosure incident.',
         'Remove public grants, validate access boundaries and assess exposure with evidence.', 'Data classification'),
    Rule('CG-STO-005','storage','Unconditioned public storage policy','HIGH',('bucket',),dangerous_policy,
         'A broad public policy lacks a modeled restriction.',
         'Replace public principals with approved identities and enforce Block Public Access.', 'Policy boundaries'),
    property_rule('CG-STO-006','storage','Legacy storage encryption absent','MEDIUM',['bucket'],
                  'encrypted',True,'Stored data lacks modeled at-rest encryption.',
                  'Verify existing object encryption and enforce the required encryption standard. Modern S3 encrypts new uploads by default.', 'Encryption at rest'),
    property_rule('CG-STO-007','storage','Storage access visibility absent','MEDIUM',['bucket'],
                  'logging_enabled',True,'Access visibility is missing in this model.',
                  'Enable approved access logging or CloudTrail data events with retention.', 'Audit visibility'),
    property_rule('CG-STO-008','storage','Storage versioning disabled','LOW',['bucket'],
                  'versioning_enabled',True,'Recovery options are limited after unintended changes.',
                  'Enable versioning where appropriate and test recovery; versioning is not a backup strategy.', 'Recoverability')]
