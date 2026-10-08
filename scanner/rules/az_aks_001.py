"""AZ-AKS-001: AKS cluster does not use a private API server endpoint."""

import logging
from typing import Any, Dict, List

from scanner.rules._aks_common import cluster_property, finding, resource_identity

RULE_ID = "AZ-AKS-001"
RULE_NAME = "AKS Private Cluster Not Enabled"
SEVERITY = "HIGH"
CATEGORY = "Kubernetes"
FRAMEWORKS = {"CIS": "N/A-AKS-001", "NIST": "PR.AC-3", "ISO27001": "A.8.20", "SOC2": "CC6.6"}
DESCRIPTION = (
    "The AKS API server is reachable through a public endpoint. Public control-plane exposure "
    "increases the opportunity for credential attacks and unauthorized cluster access."
)
REMEDIATION = "Enable the AKS private cluster feature after validating private DNS and administrator connectivity."
PLAYBOOK = "playbooks/cli/fix_az_aks_001.sh"

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
        profile = cluster_property(cluster, "api_server_access_profile")
        enabled = getattr(profile, "enable_private_cluster", None) if profile is not None else None
        if enabled is None:
            logger.warning("%s: private-cluster status unknown for %s", RULE_ID, resource_name)
            continue
        if enabled is False:
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
                    metadata={"private_cluster_enabled": False},
                )
            )
    return findings
