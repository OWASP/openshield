"""AZ-AKS-019: Workload uses an untrusted registry."""

from typing import Any, Dict, List

from scanner.rules._aks_enterprise_common import scan_control

RULE_ID = "AZ-AKS-019"
RULE_NAME = "Kubernetes Workload Uses Untrusted Registry"
SEVERITY = "HIGH"
CATEGORY = "Kubernetes"
FRAMEWORKS = {"CIS": "N/A-AKS-019", "NIST": "PR.DS-6", "ISO27001": "A.14.2.5", "SOC2": "CC8.1"}
DESCRIPTION = "A workload pulls an image from a registry outside the organization-approved trust prefixes."
REMEDIATION = "Mirror the image into an approved registry, verify it, and update the workload reference."
PLAYBOOK = "playbooks/cli/fix_az_aks_019.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    return scan_control(azure_client, globals(), "untrusted_registry")
