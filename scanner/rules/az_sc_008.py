"""AZ-SC-008: Pipeline service connection uses a password/secret instead of a federated credential."""

import logging
from typing import Any, Dict, List

from scanner.evaluation import EvaluationStatus, RuleEvaluation, fail_findings
from scanner.rules._supply_chain_common import (
    SERVICE_ENDPOINT_TYPE,
    evaluate_service_endpoints,
    evaluation,
    failed,
    missing,
)

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


def _judge(endpoint: Any, resource_id: str) -> RuleEvaluation:
    authorization = getattr(endpoint, "authorization", None)
    scheme = str(getattr(authorization, "scheme", "") or "").lower() if authorization else ""
    if not scheme:
        return missing(
            RULE_ID,
            resource_id,
            SERVICE_ENDPOINT_TYPE,
            "The service connection did not report an authorization scheme.",
        )
    evidence = {"authorization_scheme": scheme}
    if scheme in _SECRETLESS_SCHEMES:
        return evaluation(RULE_ID, resource_id, SERVICE_ENDPOINT_TYPE, EvaluationStatus.PASS, evidence=evidence)
    finding = {
        "rule_id": RULE_ID,
        "rule_name": RULE_NAME,
        "severity": SEVERITY,
        "category": CATEGORY,
        "resource_id": resource_id,
        "resource_name": getattr(endpoint, "name", ""),
        "resource_type": SERVICE_ENDPOINT_TYPE,
        "description": DESCRIPTION,
        "remediation": REMEDIATION,
        "playbook": PLAYBOOK,
        "frameworks": FRAMEWORKS,
        "metadata": {"authorization_scheme": scheme},
    }
    return failed(RULE_ID, finding, evidence)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Return the findings attached to this rule's FAIL evaluations."""
    return fail_findings(evaluate(azure_client, subscription_id))


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report a status for every AzureRM service connection, PASS included."""
    return evaluate_service_endpoints(RULE_ID, azure_client, subscription_id, _judge)
