"""Optional, account-verified READ-ONLY inventory export; never called by local scans.

Exports raw security-group data for review. It is not a full AWS-to-lab adapter.
No credential lookup or AWS request occurs until explicit account confirmation.
"""
import argparse
import json
from pathlib import Path
import re
from cloudguard.rules.secrets.redaction import mask

def collect(expected_account: str, confirmation: str, profile: str, region: str, session_factory=None):
    if not re.fullmatch(r'[0-9]{12}',expected_account) or confirmation!=expected_account:
        raise ValueError('Explicit confirmation must match the authorized 12-digit account ID.')
    if session_factory is None:
        import boto3
        session_factory=boto3.Session
    session=session_factory(profile_name=profile,region_name=region)
    identity=session.client('sts').get_caller_identity()
    if identity['Account']!=expected_account:
        raise PermissionError('Credential account does not match the explicitly authorized account.')
    groups=[]
    for page in session.client('ec2').get_paginator('describe_security_groups').paginate():
        groups.extend(page['SecurityGroups'])
    return mask({'source':'authorized-live-read-only-export','account':expected_account,
                 'region':region,'security_groups':groups,
                 'note':'Raw export only; not an Environment schema or complete assessment.'})

def main():
    parser=argparse.ArgumentParser(description='Opt-in account-verified read-only AWS inventory export')
    parser.add_argument('--expected-account',required=True)
    parser.add_argument('--confirm-live-account',required=True)
    parser.add_argument('--profile',required=True)
    parser.add_argument('--region',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        data=collect(args.expected_account,args.confirm_live_account,args.profile,args.region)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(data,indent=2,default=str),encoding='utf-8')
    except Exception:
        raise SystemExit('Read-only export failed; check confirmation, account, credentials and permissions. Details omitted.') from None
    print('Authorized inventory written locally. No configuration was modified.')

if __name__=='__main__':
    main()
