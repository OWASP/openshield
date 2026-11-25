"""AZ-SC-003: Azure Container Registry allows anonymous pull."""

import logging
from typing import Any, Dict, List

from scanner.evaluation import EvaluationStatus, RuleEvaluation, fail_findings
from scanner.rules._supply_chain_common import REGISTRY_TYPE, evaluate_registries, evaluation, failed, missing

RULE_ID = "AZ-SC-003"
RULE_NAME = "Container Registry Allows Anonymous Pull"
SEVERITY = "HIGH"
CATEGORY = "Supply Chain"
FRAMEWORKS = {"CIS": "N/A-SC-003", "NIST": "PR.AC-1", "ISO27001": "A.5.16", "SOC2": "CC6.1"}

DESCRIPTION = (
    "The Azure Container Registry allows anonymous pull, so any client on the network can pull "
    "every image in the registry without authenticating. Repository-scoped tokens cannot limit "
    "this once it is enabled; the setting applies registry-wide. If this registry is intentionally "
    "used for public OCI distribution, treat this finding as an accepted exception rather than a "
    "defect."
)

REMEDIATION = (
    "Disable anonymous pull unless the registry is deliberately used for public distribution: "
    "az acr update --name <registry> --anonymous-pull-enabled false"
)

PLAYBOOK = "playbooks/cli/fix_az_sc_003.sh"

logger = logging.getLogger(__name__)


def _judge(azure_client: Any, registry: Any, props: Any) -> RuleEvaluation:
    observed = getattr(props, "anonymous_pull_enabled", None)
    if observed is None:
        return missing(RULE_ID, registry.id, REGISTRY_TYPE, "The registry did not report anonymous_pull_enabled.")
    evidence = {"anonymous_pull_enabled": observed}
    if not observed:
        return evaluation(RULE_ID, registry.id, REGISTRY_TYPE, EvaluationStatus.PASS, evidence=evidence)
    parsed = azure_client.parse_resource_id(registry.id)
    finding = {
        "rule_id": RULE_ID,
        "rule_name": RULE_NAME,
        "severity": SEVERITY,
        "category": CATEGORY,
        "resource_id": registry.id,
        "resource_name": getattr(registry, "name", ""),
        "resource_type": REGISTRY_TYPE,
        "description": DESCRIPTION,
        "remediation": REMEDIATION,
        "playbook": PLAYBOOK,
        "frameworks": FRAMEWORKS,
        "metadata": {
            "resource_group": parsed.get("resource_group", ""),
            "anonymous_pull_enabled": True,
        },
    }
    return failed(RULE_ID, finding, evidence)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Return the findings attached to this rule's FAIL evaluations."""
    return fail_findings(evaluate(azure_client, subscription_id))


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report a status for every container registry, PASS included."""
    return evaluate_registries(
        RULE_ID, azure_client, subscription_id, lambda registry, props: _judge(azure_client, registry, props)
    )
