import json
import subprocess
import sys
import pytest
import yaml
from pydantic import ValidationError
from cloudguard.config import ROOT
from cloudguard.ingestion.loader import load_environment
from cloudguard.models.resources import Environment
from cloudguard.integrations.aws_inventory import collect
from scripts.generate_environments import secure, by_id


def test_json_and_yaml_normalize_equally(tmp_path):
    json_path, yaml_path = tmp_path/'env.json', tmp_path/'env.yaml'
    data = secure()
    json_path.write_text(json.dumps(data))
    yaml_path.write_text(yaml.safe_dump(data))
    assert load_environment(json_path) == load_environment(yaml_path)


@pytest.mark.parametrize('mutation', ['duplicate','missing_reference','missing_control','invalid_cidr','bad_port','not_synthetic'])
def test_schema_rejects_incomplete_or_inconsistent_inventory(mutation):
    data = secure()
    if mutation == 'duplicate':
        data['resources'].append(data['resources'][0])
    elif mutation == 'missing_reference':
        by_id(data,'db-customer')['properties']['security_group_ids'] = ['missing']
    elif mutation == 'missing_control':
        by_id(data,'bucket-artifacts')['properties'].pop('encrypted')
    elif mutation == 'invalid_cidr':
        by_id(data,'sg-app')['properties']['ingress'][0]['cidr'] = 'not-a-network'
    elif mutation == 'bad_port':
        by_id(data,'sg-app')['properties']['ingress'][0]['to_port'] = 65536
    else:
        data['synthetic'] = False
    with pytest.raises(ValidationError):
        Environment.model_validate(data)


@pytest.mark.parametrize('payload', ['{bad json', '!!python/object/apply:os.system ["echo forbidden"]',
                                   'a: &loop [1]\nb: *loop'])
def test_unsafe_or_malformed_input_has_safe_error(tmp_path, payload):
    path = tmp_path / ('bad.json' if payload.startswith('{') else 'bad.yaml')
    path.write_text(payload)
    with pytest.raises(ValueError, match='input values omitted'):
        load_environment(path)


def test_invalid_schema_error_does_not_echo_secret(tmp_path):
    path = tmp_path/'bad.json'
    path.write_text(json.dumps({'password':'FAKE_ERROR_VALUE'}))
    with pytest.raises(ValueError) as caught:
        load_environment(path)
    assert 'FAKE_ERROR_VALUE' not in str(caught.value)


def test_confirmation_required_before_any_sdk_call():
    def forbidden(**kwargs):
        raise AssertionError('SDK must not be called')
    with pytest.raises(ValueError):
        collect('000000000000','wrong','test','us-east-1',forbidden)


def test_wrong_account_stops_before_inventory():
    class Session:
        def client(self, service):
            assert service == 'sts'
            return self
        def get_caller_identity(self):
            return {'Account':'111111111111'}
    with pytest.raises(PermissionError):
        collect('000000000000','000000000000','test','us-east-1',lambda **kwargs:Session())


def test_read_only_collector_with_fake_sdk():
    calls = []
    class Session:
        def client(self, service):
            calls.append(service)
            return self
        def get_caller_identity(self):
            return {'Account':'000000000000'}
        def get_paginator(self, operation):
            assert operation == 'describe_security_groups'
            return self
        def paginate(self):
            return [{'SecurityGroups':[{'GroupId':'sg-lab'}]}]
    result = collect('000000000000','000000000000','test','us-east-1',lambda **kwargs:Session())
    assert calls == ['sts','ec2']
    assert result['security_groups'][0]['GroupId'] == 'sg-lab'


def test_cli_real_process_and_failure(tmp_path):
    result = subprocess.run([sys.executable,'-m','cloudguard','scan',
                             str(ROOT/'environments/environment_startup.json'),
                             '--output-dir',str(tmp_path)],cwd=ROOT,capture_output=True,text=True)
    assert result.returncode == 0
    assert 'Security Score: 46/100' in result.stdout
    assert (tmp_path/'reports/cloud-security-report.html').exists()
    missing = subprocess.run([sys.executable,'-m','cloudguard','scan','missing.json'],
                              cwd=ROOT,capture_output=True,text=True)
    assert missing.returncode == 2
    assert 'Traceback' not in missing.stderr
