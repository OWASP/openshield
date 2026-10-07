"""AZ-SC-008: Pipeline service connection uses a password/secret instead of a federated credential."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-SC-008"
RULE_NAME = "Pipeline Service Connection Uses Password Instead of Federated Credential"
SEVERITY = "MEDIUM"
CATEGORY = "Supply Chain"
FRAMEWORKS = {"CIS": "N/A-SC-008", "NIST": "PR.AC-1", "ISO27001": "A.5.17", "SOC2": "CC6.1"}

DESCRIPTION = (
    "An Azure DevOps service connection authenticates with a stored service principal secret "
    "instead of a secretless authentication scheme (workload identity federation or a managed "
    "identity). A secretless scheme has nothing to rotate or leak. A stored secret expires after "
    "a fixed period, must be rotated manually, and can be exposed through pipeline logs or "
    "variable misconfiguration in the meantime."
)

REMEDIATION = (
    "Re-create the service connection using workload identity federation or a managed identity "
    "instead of a service principal secret. See: az devops service-endpoint azurerm create with "
    "--service-principal-type federated, or the equivalent option in the Azure DevOps UI."
)

PLAYBOOK = "playbooks/cli/fix_az_sc_008.sh"

logger = logging.getLogger(__name__)

# Both schemes are secretless: workload identity federation (OIDC) and managed
# identity. Only a plain "ServicePrincipal" scheme relies on a stored secret.
_SECRETLESS_SCHEMES = {"workloadidentityfederation", "managedserviceidentity"}


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect Azure DevOps service connections using a password/secret scheme."""
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

        authorization = getattr(endpoint, "authorization", None)
        scheme = str(getattr(authorization, "scheme", "") or "").lower() if authorization else ""
        if not scheme:
            logger.warning("%s: authorization scheme unknown for %s", RULE_ID, getattr(endpoint, "name", "?"))
            continue

        if scheme not in _SECRETLESS_SCHEMES:
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
                        "authorization_scheme": scheme,
                    },
                }
            )

    return findings
