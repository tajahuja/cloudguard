import pytest
from cloudguard.engine import assess
from cloudguard.models.resources import Environment
from cloudguard.rules.registry import RULES
from scripts.generate_environments import secure, vulnerable, by_id, network


def positive_environment():
    data = vulnerable()
    by_id(data, 'sg-app')['properties']['ingress'].append(
        network(from_port=1000, to_port=5000, cidr='0.0.0.0/0'))
    return Environment.model_validate(data)


@pytest.mark.parametrize('rule', RULES, ids=lambda r: r.rule_id)
def test_rule_positive(rule):
    findings = assess(positive_environment()).findings
    matching = [f for f in findings if f.rule_id == rule.rule_id]
    assert matching, f'{rule.rule_id} did not fire on its positive case'
    for finding in matching:
        assert finding.evidence
        assert finding.remediation.steps
        assert finding.remediation.verification_steps
        assert finding.references[0].startswith('https://docs.aws.amazon.com/')


@pytest.mark.parametrize('rule', RULES, ids=lambda r: r.rule_id)
def test_rule_negative(rule):
    environment = Environment.model_validate(secure())
    matching_resources = [r for r in environment.resources if r.resource_type in rule.resource_types]
    assert matching_resources
    assert all(rule.check(environment, r) is None for r in matching_resources)


@pytest.mark.parametrize('cidr', ['0.0.0.0/0', '::/0'])
def test_global_ssh_sources(cidr):
    data = secure()
    by_id(data, 'sg-app')['properties']['ingress'] = [network(from_port=20, to_port=25, cidr=cidr)]
    assert 'CG-NET-001' in {f.rule_id for f in assess(Environment.model_validate(data)).findings}


@pytest.mark.parametrize('cidr', ['192.0.2.5/32', '198.51.100.0/24', '2001:db8::/32'])
def test_restricted_ssh_sources(cidr):
    data = secure()
    by_id(data, 'sg-app')['properties']['ingress'] = [network(from_port=22, to_port=22, cidr=cidr)]
    assert 'CG-NET-001' not in {f.rule_id for f in assess(Environment.model_validate(data)).findings}


def test_udp_22_is_not_ssh():
    data = secure()
    by_id(data, 'sg-app')['properties']['ingress'] = [network(protocol='udp', from_port=22,
                                                           to_port=22, cidr='0.0.0.0/0')]
    assert 'CG-NET-001' not in {f.rule_id for f in assess(Environment.model_validate(data)).findings}


def test_block_public_access_suppresses_effective_public_findings():
    data = secure()
    by_id(data, 'bucket-artifacts')['properties'].update(public_acl=True, anonymous_read=True,
        anonymous_write=True, policy_public=True, policy_has_conditions=False)
    assert not any(f.rule_id in {'CG-STO-001', 'CG-STO-002', 'CG-STO-003', 'CG-STO-004', 'CG-STO-005'}
                   for f in assess(Environment.model_validate(data)).findings)


def test_no_console_does_not_require_console_mfa():
    data = secure()
    by_id(data, 'user-reader')['properties'].update(console_access=False, mfa_enabled=False)
    assert 'CG-IAM-002' not in {f.rule_id for f in assess(Environment.model_validate(data)).findings}


def test_deny_and_conditioned_statements_are_not_unrestricted_allow():
    for effect, conditions in [('Deny', {}), ('Allow', {'lab_boundary': 'required'})]:
        data = secure()
        by_id(data, 'policy-read')['properties']['statements'] = [
            dict(effect=effect, actions=['*'], resources=['*'], conditions=conditions)]
        assert 'CG-IAM-003' not in {f.rule_id for f in assess(Environment.model_validate(data)).findings}


def test_key_threshold_excludes_inactive_keys():
    data = secure()
    by_id(data, 'user-reader')['properties']['access_keys'] = [
        dict(key_id='LAB-REFERENCE', active=False, age_days=999),
        dict(key_id='LAB-REFERENCE-2', active=True, age_days=90)]
    assert 'CG-IAM-004' not in {f.rule_id for f in assess(Environment.model_validate(data)).findings}


def test_ids_stable_and_resource_order_does_not_change_queue():
    data = vulnerable()
    first = assess(Environment.model_validate(data))
    data['resources'].reverse()
    second = assess(Environment.model_validate(data))
    assert [f.finding_id for f in first.findings] == [f.finding_id for f in second.findings]
    assert len({f.finding_id for f in first.findings}) == len(first.findings)
    assert first.security_score == second.security_score
