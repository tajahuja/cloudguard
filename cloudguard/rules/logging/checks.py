from cloudguard.config import MIN_RETENTION_DAYS
from cloudguard.rules.base import Rule, property_rule

def retention(e,r):
    days=r.properties.retention_days
    return {'retention_days':days,'lab_minimum_days':MIN_RETENTION_DAYS} if days<MIN_RETENTION_DAYS else None

RULES = [
    property_rule('CG-LOG-001','logging','Cloud audit logging disabled','HIGH',['audit_log'],'enabled',True,
                  'Control-plane changes may be unavailable for investigation in the modeled audit trail.',
                  'Enable audit logging and verify delivery to a protected destination.', 'Detection and accountability'),
    property_rule('CG-LOG-002','logging','Audit trail lacks multi-region coverage','MEDIUM',['audit_log'],'multi_region',True,
                  'Activities outside a single region may escape this trail.',
                  'Enable multi-region coverage and verify organization requirements.', 'Visibility coverage'),
    property_rule('CG-LOG-003','logging','Audit log validation disabled','LOW',['audit_log'],'validation_enabled',True,
                  'Integrity verification support is absent from the modeled trail.',
                  'Enable log file integrity validation and periodically verify delivered files.', 'Evidence integrity'),
    Rule('CG-LOG-004','logging','Log retention below lab baseline','MEDIUM',('audit_log','monitoring'),retention,
         'Short retention reduces the investigation lookback window.',
         'Set retention to the organization-approved duration; 90 days is this lab baseline.', 'Evidence retention'),
    property_rule('CG-LOG-005','logging','Security monitoring disabled','HIGH',['monitoring'],'enabled',True,
                  'Security events may not be evaluated for response.',
                  'Enable the approved detection service and validate alert routing.', 'Continuous monitoring')]
