"""AZ-AKS-007: AKS API server lacks approved access restrictions."""

from typing import Any, Dict, List

from scanner.rules._aks_enterprise_common import scan_control

RULE_ID = "AZ-AKS-007"
RULE_NAME = "AKS API Server Lacks Approved IP Restrictions"
SEVERITY = "HIGH"
CATEGORY = "Kubernetes"
FRAMEWORKS = {"CIS": "N/A-AKS-007", "NIST": "PR.AC-3", "ISO27001": "A.13.1.1", "SOC2": "CC6.6"}
DESCRIPTION = "A public AKS API server accepts traffic from sources outside the organization-approved IP ranges."
REMEDIATION = (
    "Use a private cluster or restrict API server authorized IP ranges to the approved administration networks."
)
PLAYBOOK = "playbooks/cli/fix_az_aks_007.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    return scan_control(azure_client, globals(), "api_restrictions")
