from scanner.rules._enterprise_resilience_common import FRAMEWORKS, scan_backup

RULE_ID = "AZ-BAK-004"
RULE_NAME = "Backup Multiuser Authorization Missing"
SEVERITY = "HIGH"
CATEGORY = "Backup"
FRAMEWORKS = {**FRAMEWORKS, "CIS": "N/A-BAK-004", "NIST": "PR.AC-4", "ISO27001": "A.8.2", "SOC2": "CC6.1"}
DESCRIPTION = "The vault does not enable Resource Guard multiuser authorization."
REMEDIATION = "Configure a separately owned Resource Guard and protect critical operations with MUA."
PLAYBOOK = "playbooks/cli/fix_az_bak_004.sh"


def _unsafe(v):
    s = v.get("multi_user_authorization")
    return None if s is None else str(s).lower() != "enabled"


def scan(azure_client, subscription_id):
    return scan_backup(azure_client, globals(), _unsafe, ["multi_user_authorization", "resource_guard_operations"])
