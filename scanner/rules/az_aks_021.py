"""AZ-AKS-021: Workload uses a mutable image reference."""

from typing import Any, Dict, List

from scanner.rules._aks_enterprise_common import scan_control

RULE_ID = "AZ-AKS-021"
RULE_NAME = "Kubernetes Workload Image Is Not Digest Pinned"
SEVERITY = "MEDIUM"
CATEGORY = "Kubernetes"
FRAMEWORKS = {"CIS": "N/A-AKS-021", "NIST": "PR.DS-6", "ISO27001": "A.14.2.5", "SOC2": "CC8.1"}
DESCRIPTION = "A workload image uses a mutable tag instead of a verified sha256 digest required by policy."
REMEDIATION = "Resolve the approved image digest and pin the workload image to its sha256 reference."
PLAYBOOK = "playbooks/cli/fix_az_aks_021.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    return scan_control(azure_client, globals(), "mutable_image")
