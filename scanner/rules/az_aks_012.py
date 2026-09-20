"""AZ-AKS-012: Secrets Store CSI rotation is disabled."""

from typing import Any, Dict, List

from scanner.rules._aks_enterprise_common import scan_control

RULE_ID = "AZ-AKS-012"
RULE_NAME = "Secrets Store CSI Secret Rotation Disabled"
SEVERITY = "MEDIUM"
CATEGORY = "Kubernetes"
FRAMEWORKS = {"CIS": "N/A-AKS-012", "NIST": "PR.AC-1", "ISO27001": "A.9.4.3", "SOC2": "CC6.1"}
DESCRIPTION = "The enabled Key Vault Secrets Store CSI provider does not automatically rotate mounted secret material."
REMEDIATION = (
    "Enable secret rotation for the AKS Key Vault Secrets Store CSI provider and test application reload behavior."
)
PLAYBOOK = "playbooks/cli/fix_az_aks_012.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    return scan_control(azure_client, globals(), "csi_rotation")
