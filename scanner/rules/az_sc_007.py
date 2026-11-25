"""AZ-SC-007: Pipeline service connection scoped to the whole subscription."""

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


def _judge(endpoint: Any, resource_id: str) -> RuleEvaluation:
    data = getattr(endpoint, "data", None) or {}
    scope_level = str(data.get("scopeLevel", "") or "").lower()
    if not scope_level:
        return missing(
            RULE_ID, resource_id, SERVICE_ENDPOINT_TYPE, "The service connection did not report a scopeLevel."
        )
    evidence = {"scope_level": scope_level}
    if scope_level != "subscription":
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
        "metadata": {
            "scope_level": scope_level,
            "is_shared_with_other_projects": bool(getattr(endpoint, "is_shared", False)),
            "subscription_id": data.get("subscriptionId", ""),
        },
    }
    return failed(RULE_ID, finding, evidence)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Return the findings attached to this rule's FAIL evaluations."""
    return fail_findings(evaluate(azure_client, subscription_id))


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report a status for every AzureRM service connection, PASS included."""
    return evaluate_service_endpoints(RULE_ID, azure_client, subscription_id, _judge)
