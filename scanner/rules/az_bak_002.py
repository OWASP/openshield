from scanner.rules._enterprise_resilience_common import FRAMEWORKS, scan_backup

RULE_ID = "AZ-BAK-002"
RULE_NAME = "Backup Vault Immutability Disabled"
SEVERITY = "HIGH"
CATEGORY = "Backup"
FRAMEWORKS = {**FRAMEWORKS, "CIS": "N/A-BAK-002", "NIST": "PR.IP-4", "ISO27001": "A.8.13", "SOC2": "A1.2"}
DESCRIPTION = "Vault immutability is disabled, allowing destructive changes to protected recovery points."
REMEDIATION = "Enable immutability after reviewing protected items and policies; do not lock it automatically."
PLAYBOOK = "playbooks/cli/fix_az_bak_002.sh"


def _unsafe(v):
    s = v.get("immutability_state")
    return None if s is None else str(s).lower() in {"disabled", "unlocked"}


def scan(azure_client, subscription_id):
    return scan_backup(azure_client, globals(), _unsafe, ["immutability_state"])
