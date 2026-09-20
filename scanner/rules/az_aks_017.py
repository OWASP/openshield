"""AZ-AKS-017: Workload mounts hostPath volumes."""

from typing import Any, Dict, List

from scanner.rules._aks_enterprise_common import scan_control

RULE_ID = "AZ-AKS-017"
RULE_NAME = "Kubernetes Workload Uses Unrestricted HostPath Volumes"
SEVERITY = "HIGH"
CATEGORY = "Kubernetes"
FRAMEWORKS = {"CIS": "N/A-AKS-017", "NIST": "PR.AC-4", "ISO27001": "A.9.4.1", "SOC2": "CC6.1"}
DESCRIPTION = "A workload mounts a path from the Kubernetes node filesystem."
REMEDIATION = "Replace hostPath with a scoped persistent volume or an approved CSI volume and enforce admission policy."
PLAYBOOK = "playbooks/cli/fix_az_aks_017.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    return scan_control(azure_client, globals(), "host_path")
