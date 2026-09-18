"""AZ-AKS-011: AKS secrets lack Key Vault or KMS-backed protection."""

from typing import Any, Dict, List

from scanner.rules._aks_enterprise_common import scan_control

RULE_ID = "AZ-AKS-011"
RULE_NAME = "AKS Secrets Lack Key Vault or KMS-Backed Protection"
SEVERITY = "HIGH"
CATEGORY = "Kubernetes"
FRAMEWORKS = {"CIS": "N/A-AKS-011", "NIST": "PR.DS-1", "ISO27001": "A.10.1.1", "SOC2": "CC6.1"}
DESCRIPTION = "A workload references native Kubernetes Secrets while Azure Key Vault KMS encryption is disabled."
REMEDIATION = (
    "Enable and validate Key Vault KMS for native Kubernetes Secrets, or configure the Key Vault Secrets Store CSI "
    "provider with Workload Identity and migrate the workload so it no longer references native Secrets."
)
PLAYBOOK = "playbooks/cli/fix_az_aks_011.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    return scan_control(azure_client, globals(), "secret_protection")
