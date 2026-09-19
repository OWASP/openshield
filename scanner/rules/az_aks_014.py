"""AZ-AKS-014: Workload shares the host network namespace."""

from typing import Any, Dict, List

from scanner.rules._aks_enterprise_common import scan_control

RULE_ID = "AZ-AKS-014"
RULE_NAME = "Kubernetes Workload Uses Host Network"
SEVERITY = "HIGH"
CATEGORY = "Kubernetes"
FRAMEWORKS = {"CIS": "N/A-AKS-014", "NIST": "PR.AC-5", "ISO27001": "A.13.1.3", "SOC2": "CC6.6"}
DESCRIPTION = "A workload explicitly shares the Kubernetes node network namespace."
REMEDIATION = "Disable hostNetwork and use Kubernetes Services or an approved network integration."
PLAYBOOK = "playbooks/cli/fix_az_aks_014.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    return scan_control(azure_client, globals(), "host_network")
