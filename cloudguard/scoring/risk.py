from math import ceil
from cloudguard.models.resources import Environment, Resource
from cloudguard.rules.iam.checks import administrator
from cloudguard.rules.storage.checks import effective_public
from cloudguard.rules.network.checks import world, weak_db_network

BASE = {'LOW': 10,'MEDIUM': 30,'HIGH': 55,'CRITICAL': 80}
def severity(value: int) -> str:
    return 'CRITICAL' if value>=80 else 'HIGH' if value>=55 else 'MEDIUM' if value>=30 else 'LOW'

def risk(base: str, environment: Environment, resource: Resource) -> tuple[int,list[str]]:
    p=resource.properties
    kind=resource.resource_type
    public = (kind=='bucket' and effective_public(environment,resource)) or (
        kind=='security_group' and any(world(n) for n in p.ingress)) or (
        kind=='instance' and bool(p.public_ip) and p.internet_route) or (
        kind=='database' and p.publicly_accessible and p.internet_route and bool(weak_db_network(environment,resource)))
    admin = kind in {'iam_user','iam_role'} and administrator(environment,resource)
    missing_mfa = kind=='iam_user' and p.console_access and not p.mfa_enabled
    encryption_gap = (hasattr(p,'encrypted') and not p.encrypted) or (kind=='instance' and not p.encrypted_volumes)
    logging_gap = (hasattr(p,'logging_enabled') and not p.logging_enabled) or (
        kind=='instance' and not p.monitoring_enabled) or (
        kind in {'audit_log','monitoring'} and not p.enabled)
    factors = [(15 if public else 0,'modeled public permission/path'),
               (15 if admin else 0,'declared administrative grant'),
               (10 if resource.sensitivity=='confidential' else 0,'confidential data context'),
               (5 if encryption_gap else 0,'encryption gap'),
               (10 if missing_mfa else 0,'console MFA absent'),
               (5 if logging_gap else 0,'visibility gap'),
               (5 if resource.criticality=='high' else 0,'high resource criticality')]
    value=BASE[base]
    reasons=[f'+{value} base {base}']
    for points,reason in factors:
        if points:
            value+=points
            reasons.append(f'+{points} {reason}')
    reasons.append('Cap at 100; priority heuristic, not breach probability.')
    return min(100,value),reasons

def posture(resource_ids: list[str], findings) -> tuple[int,dict[str,int]]:
    worst = {identifier:0 for identifier in resource_ids}
    for finding in findings:
        if finding.status != 'RESOLVED':
            worst[finding.resource_id]=max(worst[finding.resource_id],finding.risk_score)
    return 100-ceil(sum(worst.values())/len(worst)),worst
