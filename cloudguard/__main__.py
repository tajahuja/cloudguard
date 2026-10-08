import argparse
import json
import logging
from collections import Counter
from pathlib import Path
from cloudguard.config import ROOT
from cloudguard.ingestion.loader import load_environment
from cloudguard.engine import assess
from cloudguard.reporting.render import write_outputs

def main():
    parser=argparse.ArgumentParser(description='CloudGuard synthetic configuration assessment')
    commands=parser.add_subparsers(dest='command',required=True)
    scan=commands.add_parser('scan')
    scan.add_argument('input',type=Path)
    scan.add_argument('--output-dir',type=Path,default=ROOT)
    commands.add_parser('demo')
    commands.add_parser('generate')
    args=parser.parse_args()
    logging.basicConfig(level=logging.INFO,format='%(message)s')
    if args.command in {'demo','generate'}:
        from scripts.generate_environments import generate
        generate()
        if args.command=='generate':
            print('Four synthetic environments generated.')
            return
        args.input=ROOT/'environments/environment_startup.json'
        args.output_dir=ROOT
    try:
        assessment=assess(load_environment(args.input))
        _,html,_=write_outputs(assessment,args.output_dir/'findings',args.output_dir/'reports')
    except (OSError,ValueError):
        # Paths/exception values may contain sensitive material: do not echo them.
        logging.error(json.dumps({'level':'error','message':'Scan failed: invalid/unreadable input or output. Check the schema and paths.'}))
        raise SystemExit(2) from None
    counts=Counter(f.severity for f in assessment.findings)
    print('CloudGuard Security Assessment')
    print(f'Resources scanned: {assessment.resource_count}; Rules: {assessment.evaluated_rule_count}')
    for level in ['CRITICAL','HIGH','MEDIUM','LOW']:
        print(f'{level}: {counts[level]}')
    print(f'Security Score: {assessment.security_score}/100')
    print(f'Report: {html}')
    logging.info(json.dumps({'level':'info','event':'assessment_complete',
                             'resources':assessment.resource_count,'findings':len(assessment.findings),
                             'security_score':assessment.security_score}))

if __name__=='__main__':
    main()
