"""AZ-FUNC-001: Function App permits HTTP."""

from scanner.rules._enterprise_resilience_common import FRAMEWORKS, scan_functions

RULE_ID = "AZ-FUNC-001"
RULE_NAME = "Function App HTTPS Only Disabled"
SEVERITY = "HIGH"
CATEGORY = "Serverless"
FRAMEWORKS = {**FRAMEWORKS, "CIS": "N/A-FUNC-001", "NIST": "PR.DS-2", "ISO27001": "A.5.14"}
DESCRIPTION = "The Function App accepts unencrypted HTTP traffic."
REMEDIATION = "Enable HTTPS Only after validating clients."
PLAYBOOK = "playbooks/cli/fix_az_func_001.sh"


def scan(azure_client, subscription_id):
    return scan_functions(azure_client, globals(), "https_only", lambda v: v is False)
