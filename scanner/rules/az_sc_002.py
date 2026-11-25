"""AZ-SC-002: Azure Container Registry allows public network access."""

import logging
from typing import Any, Dict, List

from scanner.azure_client import enum_str
from scanner.evaluation import EvaluationStatus, RuleEvaluation, fail_findings
from scanner.rules._supply_chain_common import REGISTRY_TYPE, evaluate_registries, evaluation, failed, missing

RULE_ID = "AZ-SC-002"
RULE_NAME = "Container Registry Public Network Access Enabled"
SEVERITY = "HIGH"
CATEGORY = "Supply Chain"
FRAMEWORKS = {"CIS": "N/A-SC-002", "NIST": "PR.AC-5", "ISO27001": "A.8.20", "SOC2": "CC6.6"}

DESCRIPTION = (
    "The Azure Container Registry is reachable from the public internet. A registry that holds "
    "the container images an organization builds and deploys should only be reachable from "
    "trusted networks, the same way source code and build systems are."
)

REMEDIATION = (
    "Disable public network access and expose the registry through a private endpoint instead: "
    "az acr update --name <registry> --public-network-enabled false"
)

PLAYBOOK = "playbooks/cli/fix_az_sc_002.sh"

logger = logging.getLogger(__name__)


def _judge(azure_client: Any, registry: Any, props: Any) -> RuleEvaluation:
    observed = enum_str(getattr(props, "public_network_access", None)) or None
    if observed is None:
        return missing(RULE_ID, registry.id, REGISTRY_TYPE, "The registry did not report public_network_access.")
    evidence = {"public_network_access": observed}
    if not (observed.lower() == "enabled"):
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
            "public_network_access": observed,
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
