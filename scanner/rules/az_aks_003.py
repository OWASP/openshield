"""AZ-AKS-003: AKS cluster uses a legacy service principal."""

import logging
from typing import Any, Dict, List

from scanner.rules._aks_common import finding, resource_identity

RULE_ID = "AZ-AKS-003"
RULE_NAME = "AKS Cluster Not Using Managed Identity"
SEVERITY = "HIGH"
CATEGORY = "Kubernetes"
FRAMEWORKS = {"CIS": "N/A-AKS-003", "NIST": "PR.AC-1", "ISO27001": "A.5.16", "SOC2": "CC6.1"}
DESCRIPTION = (
    "The AKS control plane is not configured with a managed identity. Legacy service principals "
    "depend on credentials that require rotation and can be exposed or expire unexpectedly."
)
REMEDIATION = "Migrate the AKS cluster from its service principal to a system- or user-assigned managed identity."
PLAYBOOK = "playbooks/cli/fix_az_aks_003.sh"

logger = logging.getLogger(__name__)
_MANAGED_TYPES = {"systemassigned", "userassigned", "systemassigned,userassigned"}


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    clusters = azure_client.get_managed_clusters()
    if clusters is None:
        logger.warning("%s: AKS clusters could not be enumerated", RULE_ID)
        return findings
    for cluster in clusters:
        resource_id, resource_name = resource_identity(cluster)
        if not resource_id or not resource_name:
            continue
        identity = getattr(cluster, "identity", None)
        identity_type = str(getattr(identity, "type", "") or "").replace(" ", "").lower()
        if identity_type not in _MANAGED_TYPES:
            findings.append(
                finding(
                    cluster,
                    rule_id=RULE_ID,
                    rule_name=RULE_NAME,
                    severity=SEVERITY,
                    category=CATEGORY,
                    description=DESCRIPTION,
                    remediation=REMEDIATION,
                    playbook=PLAYBOOK,
                    frameworks=FRAMEWORKS,
                    metadata={"identity_type": identity_type or "service-principal"},
                )
            )
    return findings
