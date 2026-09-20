"""AZ-AKS-013: Workload permits privileged containers."""

from typing import Any, Dict, List

from scanner.rules._aks_enterprise_common import scan_control

RULE_ID = "AZ-AKS-013"
RULE_NAME = "Kubernetes Workload Permits Privileged Containers"
SEVERITY = "CRITICAL"
CATEGORY = "Kubernetes"
FRAMEWORKS = {"CIS": "N/A-AKS-013", "NIST": "PR.AC-4", "ISO27001": "A.9.4.1", "SOC2": "CC6.1"}
DESCRIPTION = "A workload explicitly enables privileged mode for an application or init container."
REMEDIATION = "Remove privileged mode and grant only the specific Linux capabilities required by the workload."
PLAYBOOK = "playbooks/cli/fix_az_aks_013.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    return scan_control(azure_client, globals(), "privileged")
