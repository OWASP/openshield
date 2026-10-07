from scanner.rules._enterprise_resilience_common import FRAMEWORKS, scan_backup

RULE_ID = "AZ-BAK-006"
RULE_NAME = "Backup Security Monitoring Disabled"
SEVERITY = "MEDIUM"
CATEGORY = "Backup"
FRAMEWORKS = {**FRAMEWORKS, "CIS": "N/A-BAK-006", "NIST": "DE.CM-1", "ISO27001": "A.8.16", "SOC2": "CC7.2"}
DESCRIPTION = "The Recovery Services vault does not enable built-in monitoring for backup job failures."
REMEDIATION = "Enable Azure Monitor alerts and route backup diagnostics to the approved monitoring destination."
PLAYBOOK = "playbooks/cli/fix_az_bak_006.sh"


def _unsafe(v):
    a = v.get("monitoring_alerts_for_job_failures")
    return None if a is None else str(a).lower() != "enabled"


def scan(azure_client, subscription_id):
    return scan_backup(azure_client, globals(), _unsafe, ["monitoring_alerts_for_job_failures"])
