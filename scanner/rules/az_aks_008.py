"""AZ-AKS-008: AKS network policy is not configured."""

from typing import Any, Dict, List

from scanner.rules._aks_enterprise_common import scan_control

RULE_ID = "AZ-AKS-008"
RULE_NAME = "AKS Cluster Has No Kubernetes Network Policy"
SEVERITY = "HIGH"
CATEGORY = "Kubernetes"
FRAMEWORKS = {"CIS": "N/A-AKS-008", "NIST": "PR.AC-5", "ISO27001": "A.13.1.3", "SOC2": "CC6.6"}
DESCRIPTION = "The AKS cluster has no supported network policy engine to enforce workload traffic boundaries."
REMEDIATION = "Enable Azure, Calico, or Cilium network policy using a tested cluster upgrade or migration plan."
PLAYBOOK = "playbooks/cli/fix_az_aks_008.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    return scan_control(azure_client, globals(), "network_policy")
