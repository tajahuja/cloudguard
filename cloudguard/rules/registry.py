from cloudguard.rules.iam.checks import RULES as IAM
from cloudguard.rules.storage.checks import RULES as STORAGE
from cloudguard.rules.network.checks import RULES as NETWORK
from cloudguard.rules.database.checks import RULES as DATABASE
from cloudguard.rules.logging.checks import RULES as LOGGING
from cloudguard.rules.compute.checks import RULES as COMPUTE
from cloudguard.rules.configuration.checks import RULES as CONFIGURATION
from cloudguard.rules.secrets.checks import RULES as SECRETS

RULES = IAM + STORAGE + NETWORK + DATABASE + LOGGING + COMPUTE + CONFIGURATION + SECRETS
assert len({r.rule_id for r in RULES}) == len(RULES), 'Rule IDs must be unique'
