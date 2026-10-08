from scanner.rules._enterprise_resilience_common import FRAMEWORKS, scan_backup

RULE_ID = "AZ-BAK-001"
RULE_NAME = "Backup Soft Delete Disabled or Below 35 Days"
SEVERITY = "CRITICAL"
CATEGORY = "Backup"
FRAMEWORKS = {**FRAMEWORKS, "CIS": "N/A-BAK-001", "NIST": "PR.IP-4", "ISO27001": "A.8.13", "SOC2": "A1.2"}
DESCRIPTION = "The Recovery Services vault lacks the approved soft-delete recovery window."
REMEDIATION = (
    "Enable enhanced soft delete and set retention to at least 35 days after reviewing cost and retention requirements."
)
PLAYBOOK = "playbooks/cli/fix_az_bak_001.sh"


def _unsafe(v):
    s = v.get("soft_delete_state")
    d = v.get("soft_delete_retention_days")
    return None if s is None or d is None else str(s).lower() not in {"enabled", "alwayson"} or d < 35


def scan(azure_client, subscription_id):
    return scan_backup(azure_client, globals(), _unsafe, ["soft_delete_state", "soft_delete_retention_days"])
