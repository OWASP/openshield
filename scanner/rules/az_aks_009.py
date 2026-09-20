"""AZ-AKS-009: Eligible namespace has no Kubernetes NetworkPolicy."""

from typing import Any, Dict, List

from scanner.rules._aks_enterprise_common import scan_control

RULE_ID = "AZ-AKS-009"
RULE_NAME = "Kubernetes Namespace Has No NetworkPolicy"
SEVERITY = "HIGH"
CATEGORY = "Kubernetes"
FRAMEWORKS = {"CIS": "N/A-AKS-009", "NIST": "PR.AC-5", "ISO27001": "A.13.1.3", "SOC2": "CC6.6"}
DESCRIPTION = "An eligible application namespace contains no NetworkPolicy and has no workload traffic boundary."
REMEDIATION = (
    "Apply tested default-deny ingress and egress policies, then add explicit workload communication allowances."
)
PLAYBOOK = "playbooks/cli/fix_az_aks_009.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    return scan_control(azure_client, globals(), "network_policy_namespaces")
