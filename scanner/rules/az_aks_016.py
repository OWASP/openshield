"""AZ-AKS-016: Workload shares the host IPC namespace."""

from typing import Any, Dict, List

from scanner.rules._aks_enterprise_common import scan_control

RULE_ID = "AZ-AKS-016"
RULE_NAME = "Kubernetes Workload Uses Host IPC Namespace"
SEVERITY = "HIGH"
CATEGORY = "Kubernetes"
FRAMEWORKS = {"CIS": "N/A-AKS-016", "NIST": "PR.AC-4", "ISO27001": "A.9.4.1", "SOC2": "CC6.1"}
DESCRIPTION = "A workload explicitly shares the Kubernetes node inter-process communication namespace."
REMEDIATION = "Disable hostIPC and use scoped application communication mechanisms."
PLAYBOOK = "playbooks/cli/fix_az_aks_016.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    return scan_control(azure_client, globals(), "host_ipc")
