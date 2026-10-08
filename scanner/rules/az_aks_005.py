"""AZ-AKS-005: Azure Policy add-on is disabled for AKS."""

import logging
from typing import Any, Dict, List, Mapping

from scanner.rules._aks_common import cluster_property, finding, resource_identity

RULE_ID = "AZ-AKS-005"
RULE_NAME = "AKS Azure Policy Add-on Not Enabled"
SEVERITY = "MEDIUM"
CATEGORY = "Kubernetes"
FRAMEWORKS = {"CIS": "N/A-AKS-005", "NIST": "PR.IP-1", "ISO27001": "A.8.9", "SOC2": "CC8.1"}
DESCRIPTION = (
    "The Azure Policy add-on is not enabled for the AKS cluster. The organization cannot centrally "
    "audit or enforce Kubernetes admission controls through Azure Policy."
)
REMEDIATION = "Enable the Azure Policy add-on and assign an appropriate AKS security initiative in audit mode first."
PLAYBOOK = "playbooks/cli/fix_az_aks_005.sh"

logger = logging.getLogger(__name__)


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
        profiles = cluster_property(cluster, "addon_profiles", {}) or {}
        azure_policy = profiles.get("azurepolicy") if isinstance(profiles, Mapping) else None
        enabled = bool(getattr(azure_policy, "enabled", False))
        if not enabled:
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
                    metadata={"azure_policy_enabled": False},
                )
            )
    return findings
