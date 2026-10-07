"""AZ-FUNC-002: Function App allows legacy TLS."""

from scanner.rules._enterprise_resilience_common import FRAMEWORKS, scan_functions

RULE_ID = "AZ-FUNC-002"
RULE_NAME = "Function App Minimum TLS Below 1.2"
SEVERITY = "HIGH"
CATEGORY = "Serverless"
FRAMEWORKS = {**FRAMEWORKS, "CIS": "N/A-FUNC-002", "NIST": "PR.DS-2", "ISO27001": "A.5.14"}
DESCRIPTION = "The Function App permits TLS older than 1.2."
REMEDIATION = "Set the minimum inbound TLS version to 1.2 or newer."
PLAYBOOK = "playbooks/cli/fix_az_func_002.sh"


def scan(azure_client, subscription_id):
    return scan_functions(azure_client, globals(), "min_tls_version", lambda v: str(v) in {"1.0", "1.1"})
