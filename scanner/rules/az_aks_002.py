"""AZ-AKS-002: AKS local administrator accounts are enabled."""

import logging
from typing import Any, Dict, List

from scanner.rules._aks_common import cluster_property, finding, resource_identity

RULE_ID = "AZ-AKS-002"
RULE_NAME = "AKS Local Accounts Enabled"
SEVERITY = "HIGH"
CATEGORY = "Kubernetes"
FRAMEWORKS = {"CIS": "N/A-AKS-002", "NIST": "PR.AC-1", "ISO27001": "A.5.16", "SOC2": "CC6.1"}
DESCRIPTION = (
    "Local AKS accounts bypass centralized Microsoft Entra identity controls and can provide "
    "long-lived cluster access outside normal conditional-access and lifecycle processes."
)
REMEDIATION = "Disable AKS local accounts after confirming Microsoft Entra administrators can access the cluster."
PLAYBOOK = "playbooks/cli/fix_az_aks_002.sh"

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
        disabled = cluster_property(cluster, "disable_local_accounts")
        if disabled is None:
            logger.warning("%s: local-account status unknown for %s", RULE_ID, resource_name)
            continue
        if disabled is False:
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
                    metadata={"local_accounts_disabled": False},
                )
            )
    return findings
