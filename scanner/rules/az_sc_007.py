"""AZ-SC-007: Pipeline service connection scoped to the whole subscription."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-SC-007"
RULE_NAME = "Pipeline Service Connection Scoped to Subscription"
SEVERITY = "HIGH"
CATEGORY = "Supply Chain"
FRAMEWORKS = {"CIS": "N/A-SC-007", "NIST": "PR.AC-4", "ISO27001": "A.8.2", "SOC2": "CC6.1"}

DESCRIPTION = (
    "An Azure DevOps service connection is scoped to the entire subscription rather than a "
    "single resource group. A service principal deploying a single App Service does not need "
    "Contributor on the whole subscription; every pipeline that uses this connection inherits "
    "subscription-wide access, including pipelines that only need to touch one resource group."
)

REMEDIATION = (
    "Re-create the service connection scoped to the resource group each pipeline actually needs "
    "instead of the whole subscription. See Azure DevOps: Project Settings > Service connections > "
    "New service connection > Azure Resource Manager > Resource Group."
)

PLAYBOOK = "playbooks/cli/fix_az_sc_007.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect Azure DevOps service connections scoped to the whole subscription."""
    findings: List[Dict[str, Any]] = []

    devops_client = getattr(azure_client, "devops_client", None)
    if devops_client is None:
        return findings

    endpoints = devops_client.get_service_endpoints()
    if endpoints is None:
        logger.warning("%s: Azure DevOps service endpoints could not be enumerated", RULE_ID)
        return findings

    for endpoint in endpoints:
        endpoint_type = getattr(endpoint, "type", "") or ""
        if endpoint_type.lower() != "azurerm":
            continue

        data = getattr(endpoint, "data", None) or {}
        scope_level = str(data.get("scopeLevel", "")).lower()

        if scope_level == "subscription":
            endpoint_id = getattr(endpoint, "id", "")
            endpoint_name = getattr(endpoint, "name", "")
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": f"azuredevops:serviceendpoint/{endpoint_id}",
                    "resource_name": endpoint_name,
                    "resource_type": "AzureDevOps/ServiceEndpoint",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "scope_level": scope_level,
                        "is_shared_with_other_projects": bool(getattr(endpoint, "is_shared", False)),
                        "subscription_id": data.get("subscriptionId", ""),
                    },
                }
            )

    return findings
