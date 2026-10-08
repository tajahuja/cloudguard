from ipaddress import ip_network
from cloudguard.rules.base import Rule

def world(rule):
    return ip_network(rule.cidr, strict=False).prefixlen == 0

def includes(rule, port):
    return rule.protocol == 'all' or (rule.protocol == 'tcp' and rule.from_port <= port <= rule.to_port)

def port_check(ports):
    def check(e,r):
        matches = [n.model_dump() for n in r.properties.ingress if world(n) and any(includes(n,p) for p in ports)]
        return {'direction':'inbound','matching_rules':matches,
                'reachability':'permitted by group; attachment, routes and listener not proved'} if matches else None
    return check

def all_ingress(e,r):
    matches = [n.model_dump() for n in r.properties.ingress if world(n) and (
        n.protocol=='all' or (n.protocol in {'tcp','udp'} and n.from_port==0 and n.to_port==65535))]
    return {'direction':'inbound','matching_rules':matches} if matches else None

def broad_ingress(e,r):
    matches = [n.model_dump() for n in r.properties.ingress if world(n) and n.protocol in {'tcp','udp'}
               and n.to_port-n.from_port >= 1000]
    return {'direction':'inbound','matching_rules':matches} if matches else None

def broad_egress(e,r):
    matches = [n.model_dump() for n in r.properties.egress if world(n) and n.protocol=='all']
    return {'direction':'outbound','matching_rules':matches,'context':'common AWS default; review requirement'} if matches else None

def weak_db_network(environment, resource):
    groups = [r for r in environment.resources if r.resource_id in resource.properties.security_group_ids]
    matches = [{'security_group': g.resource_id, **n.model_dump()} for g in groups
               for n in g.properties.ingress if world(n) and includes(n,resource.properties.port)]
    return {'port':resource.properties.port,'matching_rules':matches,
            'publicly_accessible':resource.properties.publicly_accessible,
            'internet_route':resource.properties.internet_route} if matches else None

RULES = [
    Rule('CG-NET-001','network','Security group permits public SSH','HIGH',('security_group',),port_check([22]),
         'Any source can match this SSH ingress rule; actual exposure requires an attached reachable listener.',
         'Restrict sources or use approved session-based administration instead of public SSH.', 'Minimize attack surface'),
    Rule('CG-NET-002','network','Security group permits public RDP','HIGH',('security_group',),port_check([3389]),
         'Any source can match this remote desktop rule.',
         'Remove unrestricted RDP and use approved managed administrative access.', 'Minimize attack surface'),
    Rule('CG-NET-003','network','Security group permits public database ports','HIGH',('security_group',),port_check([3306,5432,1433,27017]),
         'Database ports accept an unrestricted source in the modeled rule.',
         'Limit database traffic to application identities/networks and verify attachments.', 'Network segmentation'),
    Rule('CG-NET-004','network','Unrestricted inbound traffic','CRITICAL',('security_group',),all_ingress,
         'The group permits all protocols or the complete TCP/UDP port range from a global source.',
         'Replace with the minimum required protocols, ports and sources.', 'Default deny'),
    Rule('CG-NET-005','network','Broad public inbound port range','HIGH',('security_group',),broad_ingress,
         'A wide port range increases the potential exposed service surface.',
         'Enumerate required services and narrow each source and port range.', 'Least network privilege'),
    Rule('CG-NET-006','network','Unrestricted outbound traffic','LOW',('security_group',),broad_egress,
         'Unrestricted egress limits destination controls but may be an approved workload requirement.',
         'Review outbound needs; use scoped egress and approved proxies where feasible.', 'Egress review')]
