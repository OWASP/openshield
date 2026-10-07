"""AZ-AKS-006: AKS node OS automatic security upgrades are disabled."""

import logging
from typing import Any, Dict, List

from scanner.rules._aks_common import cluster_property, finding, resource_identity

RULE_ID = "AZ-AKS-006"
RULE_NAME = "AKS Node OS Automatic Upgrades Disabled"
SEVERITY = "HIGH"
CATEGORY = "Kubernetes"
FRAMEWORKS = {"CIS": "N/A-AKS-006", "NIST": "PR.IP-12", "ISO27001": "A.8.8", "SOC2": "CC7.1"}
DESCRIPTION = (
    "The AKS node OS upgrade channel does not automatically apply managed security updates. "
    "Worker nodes can remain exposed to operating-system vulnerabilities without a separate patch process."
)
REMEDIATION = "Set the AKS node OS upgrade channel to SecurityPatch or NodeImage and configure a maintenance window."
PLAYBOOK = "playbooks/cli/fix_az_aks_006.sh"

logger = logging.getLogger(__name__)
_COMPLIANT_CHANNELS = {"securitypatch", "nodeimage"}


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
        profile = cluster_property(cluster, "auto_upgrade_profile")
        channel = str(getattr(profile, "node_os_upgrade_channel", "") or "")
        if channel.lower() not in _COMPLIANT_CHANNELS:
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
                    metadata={"node_os_upgrade_channel": channel or "None"},
                )
            )
    return findings
