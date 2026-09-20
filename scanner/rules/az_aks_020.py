"""AZ-AKS-020: Workload uses latest or an implicit latest tag."""

from typing import Any, Dict, List

from scanner.rules._aks_enterprise_common import scan_control

RULE_ID = "AZ-AKS-020"
RULE_NAME = "Kubernetes Workload Uses Latest Image Tag"
SEVERITY = "HIGH"
CATEGORY = "Kubernetes"
FRAMEWORKS = {"CIS": "N/A-AKS-020", "NIST": "PR.IP-1", "ISO27001": "A.12.1.2", "SOC2": "CC8.1"}
DESCRIPTION = "A workload uses the latest tag or omits a tag, allowing deployments to change without a manifest change."
REMEDIATION = "Replace latest or implicit latest with an approved version and preferably a verified sha256 digest."
PLAYBOOK = "playbooks/cli/fix_az_aks_020.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    return scan_control(azure_client, globals(), "latest_image")
