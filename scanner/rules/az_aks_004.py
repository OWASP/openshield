"""AZ-AKS-004: AKS Workload Identity or OIDC issuer is disabled."""

import logging
from typing import Any, Dict, List

from scanner.rules._aks_common import cluster_property, finding, resource_identity

RULE_ID = "AZ-AKS-004"
RULE_NAME = "AKS Workload Identity Not Fully Enabled"
SEVERITY = "MEDIUM"
CATEGORY = "Kubernetes"
FRAMEWORKS = {"CIS": "N/A-AKS-004", "NIST": "PR.AC-4", "ISO27001": "A.8.2", "SOC2": "CC6.3"}
DESCRIPTION = (
    "AKS Workload Identity and its OIDC issuer are not both enabled. Applications may consequently "
    "depend on shared credentials or broader node identities when accessing Azure resources."
)
REMEDIATION = "Enable both the AKS OIDC issuer and Microsoft Entra Workload Identity, then federate each workload."
PLAYBOOK = "playbooks/cli/fix_az_aks_004.sh"

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
        oidc_profile = cluster_property(cluster, "oidc_issuer_profile")
        security_profile = cluster_property(cluster, "security_profile")
        workload_profile = getattr(security_profile, "workload_identity", None) if security_profile else None
        oidc_enabled = bool(getattr(oidc_profile, "enabled", False))
        workload_enabled = bool(getattr(workload_profile, "enabled", False))
        if not (oidc_enabled and workload_enabled):
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
                    metadata={"oidc_issuer_enabled": oidc_enabled, "workload_identity_enabled": workload_enabled},
                )
            )
    return findings
