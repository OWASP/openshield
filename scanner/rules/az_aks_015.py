"""AZ-AKS-015: Workload shares the host PID namespace."""

from typing import Any, Dict, List

from scanner.rules._aks_enterprise_common import scan_control

RULE_ID = "AZ-AKS-015"
RULE_NAME = "Kubernetes Workload Uses Host PID Namespace"
SEVERITY = "HIGH"
CATEGORY = "Kubernetes"
FRAMEWORKS = {"CIS": "N/A-AKS-015", "NIST": "PR.AC-4", "ISO27001": "A.9.4.1", "SOC2": "CC6.1"}
DESCRIPTION = "A workload explicitly shares the Kubernetes node process namespace."
REMEDIATION = "Disable hostPID and use scoped observability or management interfaces instead of node process access."
PLAYBOOK = "playbooks/cli/fix_az_aks_015.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    return scan_control(azure_client, globals(), "host_pid")
