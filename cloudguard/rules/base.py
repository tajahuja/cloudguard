from dataclasses import dataclass
from typing import Callable
from cloudguard.models.resources import Environment, Resource
from cloudguard.models.findings import Severity

REFERENCES = {
    'iam': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
    'storage': 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html',
    'network': 'https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html',
    'database': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.html',
    'logging': 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html',
    'compute': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html',
    'secrets': 'https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html',
    'configuration': 'https://docs.aws.amazon.com/tag-editor/latest/userguide/best-practices-and-strats.html'}

@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    title: str
    base_severity: Severity
    resource_types: tuple[str, ...]
    check: Callable[[Environment, Resource], dict | None]
    impact: str
    remediation: str
    principle: str

def check_field(field: str, expected):
    def check(environment, resource):
        actual = getattr(resource.properties, field)
        return {field: actual, 'expected': expected} if actual != expected else None
    return check

def property_rule(identifier, category, title, severity, kinds, field, expected,
                  impact, remediation, principle):
    return Rule(identifier, category, title, severity, tuple(kinds),
                check_field(field, expected), impact, remediation, principle)
