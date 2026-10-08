import hashlib
from collections import Counter
from cloudguard.models.findings import Finding, Assessment
from cloudguard.models.resources import Environment
from cloudguard.rules.base import REFERENCES
from cloudguard.rules.registry import RULES
from cloudguard.rules.secrets.redaction import mask
from cloudguard.scoring.risk import risk, severity, posture
from cloudguard.remediation.guidance import guidance

def assess(environment: Environment) -> Assessment:
    findings=[]
    for resource in environment.resources:
        for rule in RULES:
            if resource.resource_type not in rule.resource_types:
                continue
            evidence=rule.check(environment,resource)
            if evidence is None:
                continue
            score,reasons=risk(rule.base_severity,environment,resource)
            rating=severity(score)
            key=f'{environment.account_alias}|{resource.resource_id}|{rule.rule_id}'
            findings.append(Finding(
                finding_id=rule.rule_id+'-'+hashlib.sha256(key.encode()).hexdigest()[:10],
                rule_id=rule.rule_id, category=rule.category, title=rule.title,
                description=f'{rule.title} requires review against the intended workload baseline.',
                resource_id=resource.resource_id,resource_type=resource.resource_type,
                resource_name=mask(resource.name),severity=rating,base_severity=rule.base_severity,
                risk_score=score,risk_reasons=reasons,evidence=mask(evidence),
                security_impact=rule.impact,
                attack_scenario='Hypothetical impact: '+rule.impact+' No abuse or compromise is observed by this configuration assessment.',
                remediation=guidance(rule,rating),references=[REFERENCES[rule.category]],
                framework_mapping=['AWS security best-practice concept: '+rule.principle]))
    findings.sort(key=lambda f:(-f.risk_score,f.rule_id,f.resource_id))
    score,risks=posture([r.resource_id for r in environment.resources],findings)
    counts=Counter(f.severity for f in findings)
    categories=Counter(f.category for f in findings)
    top=', '.join(category for category,_ in categories.most_common(3)) or 'none identified'
    summary=(f'The synthetic environment contains {len(environment.resources)} resources and '
             f'{len(findings)} findings, including {counts["CRITICAL"]} critical and {counts["HIGH"]} high. '
             f'The educational security score is {score}/100. Leading finding categories: {top}. '
             'Prioritize the highest-risk resource configurations, validate context, and apply approved remediation. '
             'No exploitation or incident confirmation was performed.')
    return Assessment(environment_name=mask(environment.name),assessed_at=environment.assessed_at,
                      resource_count=len(environment.resources),evaluated_rule_count=len(RULES),
                      security_score=score,resource_risks=risks,findings=findings,summary=summary)
