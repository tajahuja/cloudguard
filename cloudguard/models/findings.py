from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field

Severity = Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

class Remediation(BaseModel):
    steps: list[str]
    recommended_configuration: str
    principle: str
    verification_steps: list[str]
    urgency: str

class Finding(BaseModel):
    finding_id: str
    rule_id: str
    category: str
    title: str
    description: str
    resource_id: str
    resource_type: str
    resource_name: str
    severity: Severity
    base_severity: Severity
    risk_score: int = Field(ge=0, le=100)
    risk_reasons: list[str]
    evidence: dict[str, Any]
    security_impact: str
    attack_scenario: str
    remediation: Remediation
    references: list[str]
    framework_mapping: list[str]
    status: Literal['OPEN', 'ACCEPTED', 'RESOLVED'] = 'OPEN'

class Assessment(BaseModel):
    environment_name: str
    assessed_at: datetime
    resource_count: int
    evaluated_rule_count: int
    security_score: int = Field(ge=0, le=100)
    resource_risks: dict[str, int]
    findings: list[Finding]
    summary: str
