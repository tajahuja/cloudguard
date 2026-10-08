from cloudguard.rules.base import Rule, property_rule
from cloudguard.rules.network.checks import weak_db_network

def public_db(e,r):
    return {'publicly_accessible':True,'internet_route':r.properties.internet_route,
            'actual_reachability':'requires permitted network path and listener'} if r.properties.publicly_accessible else None

def sensitive_db(e,r):
    return {'sensitivity':'confidential',**public_db(e,r)} if r.sensitivity=='confidential' and r.properties.publicly_accessible else None

RULES = [
    Rule('CG-DB-001','database','Database public accessibility enabled','HIGH',('database',),public_db,
         'Public addressing increases potential exposure; it does not alone prove internet reachability.',
         'Disable public accessibility unless justified and verify private routing.', 'Private data tier'),
    Rule('CG-DB-002','database','Confidential database has public accessibility','CRITICAL',('database',),sensitive_db,
         'Confidential data deserves stronger network isolation.',
         'Move the data tier to private access and review evidence of access.', 'Data protection'),
    Rule('CG-DB-003','database','Database has globally permitted ingress','HIGH',('database',),weak_db_network,
         'A referenced security group permits the database port from a global source.',
         'Permit database traffic only from approved application groups; verify routes and listeners.', 'Network segmentation'),
    property_rule('CG-DB-004','database','Database encryption disabled','HIGH',['database'],'encrypted',True,
                  'Database storage lacks modeled at-rest encryption.',
                  'Plan a supported encrypted migration with tested backup and restore.', 'Encryption at rest'),
    property_rule('CG-DB-005','database','Database backups disabled','MEDIUM',['database'],'backups_enabled',True,
                  'Recovery from loss or corruption is impaired.',
                  'Configure approved backup retention and test restore.', 'Recoverability'),
    property_rule('CG-DB-006','database','Database deletion protection disabled','LOW',['database'],'deletion_protection',True,
                  'An accidental administrative deletion has fewer safeguards.',
                  'Enable deletion protection where workload lifecycle permits.', 'Change protection'),
    property_rule('CG-DB-007','database','Database logging disabled','MEDIUM',['database'],'logging_enabled',True,
                  'Database activity has reduced investigation visibility.',
                  'Enable appropriate engine/audit logs and secure their retention.', 'Audit visibility')]
