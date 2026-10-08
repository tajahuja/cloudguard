"""A strict, deliberately simplified AWS-style configuration schema."""
from datetime import datetime, timezone
from ipaddress import ip_network, ip_address
from typing import Annotated, Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)

class Statement(StrictModel):
    effect: Literal['Allow', 'Deny']
    actions: list[str]
    resources: list[str]
    conditions: dict[str, Any] = Field(default_factory=dict)

class AccessKey(StrictModel):
    key_id: str
    active: bool
    age_days: int = Field(ge=0)

class Identity(StrictModel):
    console_access: bool
    mfa_enabled: bool
    is_root: bool = False
    last_used_days: int = Field(ge=0)
    managed_policies: list[str]
    policy_ids: list[str]
    inline_statements: list[Statement]
    access_keys: list[AccessKey]
    trust_principals: list[str]
    trust_has_conditions: bool

class Policy(StrictModel):
    statements: list[Statement]

class Bucket(StrictModel):
    block_public_access: bool
    public_acl: bool
    anonymous_read: bool
    anonymous_write: bool
    policy_public: bool
    policy_has_conditions: bool
    encrypted: bool
    logging_enabled: bool
    versioning_enabled: bool

class NetworkRule(StrictModel):
    protocol: Literal['tcp', 'udp', 'icmp', 'all']
    from_port: int = Field(ge=0, le=65535)
    to_port: int = Field(ge=0, le=65535)
    cidr: str
    @field_validator('cidr')
    @classmethod
    def valid_cidr(cls, value):
        ip_network(value, strict=False)
        return value
    @model_validator(mode='after')
    def ordered(self):
        if self.to_port < self.from_port:
            raise ValueError('invalid port range')
        return self

class SecurityGroup(StrictModel):
    ingress: list[NetworkRule]
    egress: list[NetworkRule]

class Instance(StrictModel):
    public_ip: str | None
    internet_route: bool
    security_group_ids: list[str]
    encrypted_volumes: bool
    imdsv2_required: bool
    monitoring_enabled: bool
    @field_validator('public_ip')
    @classmethod
    def valid_ip(cls, value):
        if value:
            ip_address(value)
        return value

class Database(StrictModel):
    publicly_accessible: bool
    internet_route: bool
    port: int = Field(ge=1, le=65535)
    security_group_ids: list[str]
    encrypted: bool
    backups_enabled: bool
    deletion_protection: bool
    logging_enabled: bool

class AuditLog(StrictModel):
    enabled: bool
    multi_region: bool
    validation_enabled: bool
    retention_days: int = Field(ge=0)

class Monitoring(StrictModel):
    enabled: bool
    retention_days: int = Field(ge=0)

SETTINGS = {'iam_user': Identity, 'iam_role': Identity, 'iam_policy': Policy,
            'bucket': Bucket, 'security_group': SecurityGroup, 'instance': Instance,
            'database': Database, 'audit_log': AuditLog, 'monitoring': Monitoring}

class Resource(StrictModel):
    resource_id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=150)
    resource_type: Literal['iam_user','iam_role','iam_policy','bucket','security_group',
                           'instance','database','audit_log','monitoring']
    region: str
    tags: dict[str, str]
    sensitivity: Literal['public', 'internal', 'confidential']
    criticality: Literal['low', 'medium', 'high']
    properties: Any
    configuration: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode='after')
    def parse_properties(self):
        expected = SETTINGS[self.resource_type]
        if not isinstance(self.properties, expected):
            self.properties = expected.model_validate(self.properties)
        return self

class Environment(StrictModel):
    schema_version: Literal['1.0']
    synthetic: Literal[True]
    name: str
    organization: str
    account_alias: str
    assessed_at: Annotated[datetime, Field(strict=False)]
    resources: list[Resource] = Field(min_length=1, max_length=1000)

    @field_validator('assessed_at')
    @classmethod
    def utc(cls, value):
        if value.tzinfo is None:
            raise ValueError('timezone required')
        return value.astimezone(timezone.utc)

    @model_validator(mode='after')
    def references(self):
        ids = [r.resource_id for r in self.resources]
        if len(set(ids)) != len(ids):
            raise ValueError('duplicate resource IDs')
        lookup = {r.resource_id: r.resource_type for r in self.resources}
        for r in self.resources:
            for attribute, kind in [('policy_ids', 'iam_policy'), ('security_group_ids', 'security_group')]:
                for identifier in getattr(r.properties, attribute, []):
                    if lookup.get(identifier) != kind:
                        raise ValueError('missing or incorrect resource reference')
        return self
