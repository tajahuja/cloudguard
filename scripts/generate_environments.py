"""Four deterministic inventories. Placeholder credentials are intentionally invalid."""
from copy import deepcopy
import json
from cloudguard.config import ROOT

def network(protocol='tcp',from_port=443,to_port=443,cidr='192.0.2.0/24'):
    return dict(protocol=protocol,from_port=from_port,to_port=to_port,cidr=cidr)

def resource(identifier,kind,properties,sensitivity='internal',criticality='medium'):
    return dict(resource_id=identifier,name='lab-'+identifier,resource_type=kind,
                region='us-east-1',tags={'owner':'lab-platform-team','environment':'lab'},
                sensitivity=sensitivity,criticality=criticality,properties=properties,configuration={})

def identity():
    return dict(console_access=True,mfa_enabled=True,is_root=False,last_used_days=2,
                managed_policies=[],policy_ids=['policy-read'],inline_statements=[],access_keys=[],
                trust_principals=['compute.example.test'],trust_has_conditions=True)

def secure():
    resources=[
        resource('policy-read','iam_policy',dict(statements=[dict(effect='Allow',
                  actions=['s3:GetObject'],resources=['arn:aws:s3:::lab-artifacts/*'],conditions={})])),
        resource('user-reader','iam_user',identity()),
        resource('role-worker','iam_role',identity()),
        resource('bucket-artifacts','bucket',dict(block_public_access=True,public_acl=False,
                  anonymous_read=False,anonymous_write=False,policy_public=False,policy_has_conditions=True,
                  encrypted=True,logging_enabled=True,versioning_enabled=True)),
        resource('sg-app','security_group',dict(ingress=[network(from_port=22,to_port=22)],
                  egress=[network()])),
        resource('sg-db','security_group',dict(ingress=[network(from_port=5432,to_port=5432)],
                  egress=[network()])),
        resource('vm-app','instance',dict(public_ip=None,internet_route=False,security_group_ids=['sg-app'],
                  encrypted_volumes=True,imdsv2_required=True,monitoring_enabled=True)),
        resource('db-customer','database',dict(publicly_accessible=False,internet_route=False,port=5432,
                  security_group_ids=['sg-db'],encrypted=True,backups_enabled=True,
                  deletion_protection=True,logging_enabled=True),sensitivity='confidential',criticality='high'),
        resource('trail-control','audit_log',dict(enabled=True,multi_region=True,
                  validation_enabled=True,retention_days=365)),
        resource('monitor-security','monitoring',dict(enabled=True,retention_days=180))]
    return dict(schema_version='1.0',synthetic=True,name='HarborLab secure baseline',
                organization='HarborLab Fictional',account_alias='lab-account-secure',
                assessed_at='2026-10-08T09:00:00Z',resources=resources)

def by_id(environment,identifier):
    return next(r for r in environment['resources'] if r['resource_id']==identifier)

def startup():
    environment=secure()
    environment.update(name='HarborLab startup',account_alias='lab-account-startup')
    user=by_id(environment,'user-reader')
    user['name']='lab-startup-admin'
    user['criticality']='high'
    user['properties'].update(mfa_enabled=False,last_used_days=130,
                              managed_policies=['AdministratorAccess'],
                              access_keys=[dict(key_id='LAB-KEY-REFERENCE-1',active=True,age_days=210)])
    by_id(environment,'bucket-artifacts').update(sensitivity='confidential')
    by_id(environment,'bucket-artifacts')['properties'].update(block_public_access=False,
                      anonymous_read=True,policy_public=True,policy_has_conditions=False,logging_enabled=False)
    by_id(environment,'sg-app')['properties']['ingress']=[network(from_port=22,to_port=22,cidr='0.0.0.0/0')]
    by_id(environment,'sg-db')['properties']['ingress']=[network(from_port=5432,to_port=5432,cidr='::/0')]
    by_id(environment,'db-customer')['properties'].update(publicly_accessible=True,internet_route=True,
                      encrypted=False,backups_enabled=False,logging_enabled=False)
    by_id(environment,'trail-control')['properties'].update(enabled=False,retention_days=14)
    by_id(environment,'vm-app')['configuration']={'database_password':'FAKE_DO_NOT_USE_DEMO_PASSWORD'}
    return environment

def vulnerable():
    environment=startup()
    environment.update(name='HarborLab vulnerable legacy mock',account_alias='lab-account-vulnerable')
    by_id(environment,'policy-read')['properties']['statements']=[dict(effect='Allow',actions=['*'],resources=['*'],conditions={})]
    user=by_id(environment,'user-reader')['properties']
    user['is_root']=True
    user['access_keys'].append(dict(key_id='LAB-KEY-REFERENCE-2',active=True,age_days=250))
    role=by_id(environment,'role-worker')['properties']
    role.update(trust_principals=['*'],trust_has_conditions=False,policy_ids=[])
    role['inline_statements']=[dict(effect='Allow',actions=['iam:PassRole','ec2:RunInstances'],resources=['*'],conditions={})]
    by_id(environment,'bucket-artifacts')['properties'].update(anonymous_write=True,public_acl=True,
                      encrypted=False,versioning_enabled=False)
    by_id(environment,'sg-app')['properties'].update(
        ingress=[network(protocol='all',from_port=0,to_port=65535,cidr='0.0.0.0/0'),
                 network(from_port=3389,to_port=3389,cidr='::/0')],
        egress=[network(protocol='all',from_port=0,to_port=65535,cidr='::/0')])
    by_id(environment,'db-customer')['properties']['deletion_protection']=False
    by_id(environment,'vm-app')['properties'].update(public_ip='203.0.113.25',internet_route=True,
                      encrypted_volumes=False,imdsv2_required=False,monitoring_enabled=False)
    by_id(environment,'vm-app')['configuration'].update(
        api_key='FAKE_API_KEY_NOT_VALID',note='AKIA_FAKE_PLACEHOLDER_TEST',
        private_key='-----BEGIN PRIVATE KEY-----FAKE-INVALID-TEST-----END PRIVATE KEY-----')
    by_id(environment,'trail-control')['properties'].update(multi_region=False,validation_enabled=False)
    by_id(environment,'monitor-security')['properties'].update(enabled=False,retention_days=7)
    by_id(environment,'vm-app')['tags']={}
    return environment

def enterprise():
    environment=secure()
    environment.update(name='HarborLab enterprise review',account_alias='lab-account-enterprise')
    for index in range(1,4):
        copies=deepcopy(secure()['resources'])
        rename={r['resource_id']:r['resource_id']+f'-{index}' for r in copies}
        for r in copies:
            r['resource_id']=rename[r['resource_id']]
            r['name']+=f'-{index}'
            for key in ['policy_ids','security_group_ids']:
                if key in r['properties']:
                    r['properties'][key]=[rename[i] for i in r['properties'][key]]
            environment['resources'].append(r)
    by_id(environment,'user-reader-1')['properties']['access_keys']=[dict(key_id='LAB-KEY-REFERENCE-OLD',active=True,age_days=160)]
    by_id(environment,'bucket-artifacts-2')['properties']['versioning_enabled']=False
    by_id(environment,'trail-control-3')['properties']['retention_days']=30
    by_id(environment,'vm-app-2')['tags'].pop('owner')
    return environment

def generate():
    folder=ROOT/'environments'
    folder.mkdir(parents=True,exist_ok=True)
    for name,builder in [('secure',secure),('startup',startup),('vulnerable',vulnerable),('enterprise',enterprise)]:
        (folder/f'environment_{name}.json').write_text(json.dumps(builder(),indent=2)+'\n',encoding='utf-8')
    return folder

if __name__=='__main__':
    print(generate())
