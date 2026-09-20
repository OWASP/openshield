"""AZ-AKS-018: cluster-admin access is assigned too broadly."""

from typing import Any, Dict, List

from scanner.rules._aks_enterprise_common import scan_control

RULE_ID = "AZ-AKS-018"
RULE_NAME = "Kubernetes Cluster Admin Access Assigned Too Broadly"
SEVERITY = "CRITICAL"
CATEGORY = "Kubernetes"
FRAMEWORKS = {"CIS": "N/A-AKS-018", "NIST": "PR.AC-4", "ISO27001": "A.9.2.3", "SOC2": "CC6.3"}
DESCRIPTION = (
    "A ClusterRoleBinding grants cluster-admin to a subject outside the approved platform administrator allowlist."
)
REMEDIATION = (
    "Remove the broad binding and replace it with namespace-scoped, least-privilege roles for approved groups."
)
PLAYBOOK = "playbooks/cli/fix_az_aks_018.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    return scan_control(azure_client, globals(), "cluster_admin")
