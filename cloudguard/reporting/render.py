from collections import Counter
from jinja2 import Environment, FileSystemLoader, select_autoescape
from cloudguard.config import ROOT
from cloudguard.models.findings import Assessment
from cloudguard.rules.secrets.redaction import mask

LIMITATIONS = ('Synthetic configuration snapshot only. Declared permissions are not a full AWS authorization simulation. '
               'Network grants do not prove reachable services. No live account, compliance certification or compromise verification. '
               'Scores are educational priorities; redaction is defense in depth, not a guarantee for arbitrary input formats.')

def html_report(assessment: Assessment) -> str:
    templates=Environment(loader=FileSystemLoader(ROOT/'cloudguard/reporting/templates'),
                          autoescape=select_autoescape(['html']))
    return templates.get_template('assessment.html').render(
        assessment=assessment,counts=Counter(f.severity for f in assessment.findings),limitations=LIMITATIONS)

def markdown_report(assessment: Assessment) -> str:
    sections=[f'# CloudGuard — {assessment.environment_name}', '## Executive Summary',assessment.summary,
              '## Environment Overview',f'Assessment time: {assessment.assessed_at.isoformat()}. '
              f'Resources: {assessment.resource_count}. Rules: {assessment.evaluated_rule_count}.',
              '## Cloud Security Score',f'{assessment.security_score}/100. See docs/scoring.md for the formula.',
              '## Risk Distribution',str(dict(Counter(f.severity for f in assessment.findings))),
              '## Prioritized Action Plan']
    for position,f in enumerate(assessment.findings,1):
        sections.extend([f'### {position}. {f.title} ({f.severity}, {f.risk_score}/100)',
                         f'Finding: {f.finding_id}. Affected resource: {f.resource_type}/{f.resource_name}.',
                         'Evidence: '+str(mask(f.evidence)), 'Impact: '+f.security_impact,
                         'Hypothesis: '+f.attack_scenario, 'Urgency: '+f.remediation.urgency,
                         'Remediation: '+' '.join(f.remediation.steps),
                         'Verification: '+' '.join(f.remediation.verification_steps)])
    sections.extend(['## Limitations',LIMITATIONS,'## Conclusion',
                     'Use this assessment as a review queue. Validate context, preserve evidence and retest approved changes.'])
    return '\n\n'.join(sections)+'\n'

def write_outputs(assessment: Assessment, findings_dir=ROOT/'findings', reports_dir=ROOT/'reports'):
    findings_dir.mkdir(parents=True,exist_ok=True)
    reports_dir.mkdir(parents=True,exist_ok=True)
    paths=[findings_dir/'latest-assessment.json',reports_dir/'cloud-security-report.html',
           reports_dir/'cloud-security-report.md']
    contents=[assessment.model_dump_json(indent=2),html_report(assessment),markdown_report(assessment)]
    for path,content in zip(paths,contents):
        temporary=path.with_suffix(path.suffix+'.tmp')
        temporary.write_text(content,encoding='utf-8')
        temporary.replace(path)
    return paths
