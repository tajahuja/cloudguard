import json
import pytest
from cloudguard.models.resources import Environment
from cloudguard.engine import assess
from cloudguard.scoring.risk import risk, severity, posture
from cloudguard.reporting.render import html_report, markdown_report, write_outputs
from cloudguard.rules.secrets.redaction import mask, secret_paths
from cloudguard.ingestion.loader import load_environment
from scripts.generate_environments import secure, startup, vulnerable, enterprise, by_id


@pytest.mark.parametrize('value,expected', [(0,'LOW'),(29,'LOW'),(30,'MEDIUM'),(54,'MEDIUM'),
                                          (55,'HIGH'),(79,'HIGH'),(80,'CRITICAL'),(100,'CRITICAL')])
def test_severity_boundaries(value, expected):
    assert severity(value) == expected


def test_risk_context_and_cap():
    environment = Environment.model_validate(startup())
    admin = next(r for r in environment.resources if r.resource_id == 'user-reader')
    score, reasons = risk('HIGH', environment, admin)
    assert score == 85  # 55 + admin 15 + MFA 10 + criticality 5
    assert any('+15 declared administrative' in r for r in reasons)
    assert risk('CRITICAL', environment, admin)[0] == 100


def test_posture_worst_per_resource_not_finding_count():
    finding = assess(Environment.model_validate(startup())).findings[0]
    finding.risk_score = 81
    score, risks = posture([finding.resource_id, 'safe-resource'], [finding, finding])
    assert score == 59  # 100 - ceil(81/2)
    assert risks['safe-resource'] == 0
    finding.status = 'RESOLVED'
    assert posture([finding.resource_id], [finding])[0] == 100
    finding.status = 'ACCEPTED'
    assert posture([finding.resource_id], [finding])[0] == 19


@pytest.mark.parametrize('builder,expected_count,expected_score',
                         [(secure,0,100),(startup,20,46),(vulnerable,43,22),(enterprise,4,98)])
def test_environment_regressions(builder, expected_count, expected_score):
    assessment = assess(Environment.model_validate(builder()))
    assert len(assessment.findings) == expected_count
    assert assessment.security_score == expected_score


def test_secret_redaction_nested_and_patterns():
    data = {'password':'FAKE_RAW_VALUE','nested':[{'api_key':'FAKE_API_KEY_VALUE'}],
            'note':'AKIA_FAKE_PLACEHOLDER_TEST',
            'key':'-----BEGIN PRIVATE KEY-----FAKE-INVALID-----END PRIVATE KEY-----'}
    scrubbed = json.dumps(mask(data))
    for value in ['FAKE_RAW_VALUE','FAKE_API_KEY_VALUE','AKIA_FAKE_PLACEHOLDER_TEST','FAKE-INVALID']:
        assert value not in scrubbed
    assert len(secret_paths(data)) == 4


def test_secret_values_never_enter_reports(tmp_path):
    data = vulnerable()
    source = tmp_path / 'input.json'
    source.write_text(json.dumps(data), encoding='utf-8')
    assessment = assess(load_environment(source))
    assert 'CG-SEC-001' in {f.rule_id for f in assessment.findings}
    all_output = html_report(assessment) + markdown_report(assessment) + assessment.model_dump_json()
    for value in ['FAKE_DO_NOT_USE_DEMO_PASSWORD','FAKE_API_KEY_NOT_VALID','AKIA_FAKE_PLACEHOLDER_TEST',
                  'FAKE-INVALID-TEST']:
        assert value not in all_output
    assert '[REDACTED]' in all_output


def test_html_report_escapes_resource_content():
    data = startup()
    by_id(data, 'user-reader')['name'] = '<script>alert("test")</script>'
    assessment = assess(Environment.model_validate(data))
    result = html_report(assessment)
    assert '<script>' not in result
    assert '&lt;script&gt;' in result
    for section in ['Executive Summary','Environment Overview','Cloud Security Score',
                    'Risk Distribution','Critical Findings','High Findings','Affected Resources',
                    'Prioritized Action Plan','Limitations','Conclusion']:
        assert section in result


def test_generated_outputs_are_valid(tmp_path):
    assessment = assess(Environment.model_validate(startup()))
    paths = write_outputs(assessment, tmp_path/'findings', tmp_path/'reports')
    assert all(path.exists() for path in paths)
    assert json.loads(paths[0].read_text())['security_score'] == 46
    assert '<!doctype html>' in paths[1].read_text()
    assert 'CG-IAM-' in paths[2].read_text()
