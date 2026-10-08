from cloudguard.models.findings import Remediation

URGENCY = {'CRITICAL':'Immediate owner review; plan containment if exposure is confirmed.',
           'HIGH':'Prioritize in the next approved remediation cycle.',
           'MEDIUM':'Schedule a documented control improvement.',
           'LOW':'Review against the workload baseline and track a decision.'}

def guidance(rule, severity):
    return Remediation(steps=[rule.remediation,'Validate dependencies and approve the change before applying it.'],
                       recommended_configuration=rule.remediation,
                       principle=rule.principle,
                       verification_steps=['Export the updated configuration and rerun this rule.',
                                           'Confirm intended access and recovery behavior using authorized validation.'],
                       urgency=URGENCY[severity])
