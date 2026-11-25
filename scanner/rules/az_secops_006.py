"""AZ-SECOPS-006: Required Defender for Cloud protection is missing for a critical workload."""

import logging
from typing import Any, Dict, List

from scanner.evaluation import POLICY_NOT_REQUIRED, RuleEvaluation, fail_findings, subscription_scope_id
from scanner.rules._security_operations_common import (
    build_collector,
    build_finding,
    collection_failed,
    failed,
    is_usable,
    not_applicable,
    passed,
    prepare,
    value,
)

logger = logging.getLogger(__name__)

RULE_ID = "AZ-SECOPS-006"
RULE_NAME = "Required Microsoft Defender for Cloud Plan Not Enabled"
SEVERITY = "HIGH"
CATEGORY = "Security Operations"
FRAMEWORKS = {"CIS": "N/A-SECOPS-006", "NIST": "DE.CM-8", "ISO27001": "A.8.8", "SOC2": "CC7.1"}

# The CIS Azure Foundations Benchmark maps each Defender plan to its own leaf
# control (e.g. 2.1.1 Servers, 2.1.7 Storage, 2.1.5 SQL Servers on Machines,
# 2.1.4 Azure SQL Databases). This rule is policy-driven across whatever
# plans the organisation names in required_defender_plans, so no single
# fixed control_id applies at the module level (see FRAMEWORKS["CIS"]
# above and tests/test_cis_benchmark_mapping.py's one-CIS-control-per-rule
# invariant); the real per-plan control is attached per finding instead.
_CIS_PLAN_CONTROLS = {
    "virtualmachines": "2.1.1",
    "appservices": "2.1.2",
    "azurecosmosdb": "2.1.9",
    "sqlservers": "2.1.4",
    "sqlservervirtualmachines": "2.1.5",
    "opensourcerelationaldatabases": "2.1.6",
    "storageaccounts": "2.1.7",
    "containers": "2.1.8",
    "keyvaults": "2.1.10",
    "arm": "2.1.12",
}

DESCRIPTION = (
    "A Microsoft Defender for Cloud plan the organisation requires for critical workloads (e.g. "
    "VirtualMachines, StorageAccounts, SqlServers) is not enabled (pricing tier is not 'Standard') "
    "at the subscription scope. Without the plan enabled, the corresponding workload type receives "
    "no Defender threat detection, and no recommendations or alerts are generated for it."
)
REMEDIATION = (
    "Enable the required Defender plan at subscription scope, e.g.:\n"
    "  az security pricing create --name <PlanName> --tier Standard"
)
PLAYBOOK = "playbooks/cli/fix_az_secops_006.sh"
_RESOURCE_TYPE = "Microsoft.Security/pricings"

_ENABLED_TIERS = {"standard"}


def _plan_name(pricing: Any) -> str:
    return str(value(pricing, "name") or "").strip()


def _is_enabled(pricing: Any) -> bool:
    tier = value(pricing, "pricing_tier")
    tier_str = str(getattr(tier, "value", tier) or "").strip().lower()
    return tier_str in _ENABLED_TIERS


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Return the findings attached to this rule's FAIL evaluations."""
    return fail_findings(evaluate(azure_client, subscription_id))


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report, per organisation-required Defender plan, whether it is set to Standard."""
    collector, policy, early = prepare(RULE_ID, _RESOURCE_TYPE, azure_client, subscription_id, build_collector)
    if early is not None:
        return early
    if not policy.required_defender_plans:
        return [
            not_applicable(
                RULE_ID,
                subscription_scope_id(subscription_id),
                _RESOURCE_TYPE,
                POLICY_NOT_REQUIRED,
                "The security-operations policy requires no Defender plans.",
            )
        ]

    result = collector.defender_pricings()
    if not is_usable(result):
        return [collection_failed(RULE_ID, _RESOURCE_TYPE, subscription_id, result)]

    enabled_plans = {_plan_name(p).lower() for p in result.items if _is_enabled(p)}
    all_plan_names = {_plan_name(p) for p in result.items if _plan_name(p)}
    # Case-insensitive comparison: policy plan names are normalised lowercase
    # by load_security_operations_policy, Azure plan names are PascalCase.
    plan_lookup = {name.lower(): name for name in all_plan_names}

    evaluations: List[RuleEvaluation] = []
    for required_plan in sorted(policy.required_defender_plans):
        display_name = plan_lookup.get(required_plan, required_plan)
        resource_id = f"/subscriptions/{subscription_id}/providers/Microsoft.Security/pricings/{display_name}"
        evidence = {
            "plan": display_name,
            "plan_found_in_subscription": display_name in all_plan_names,
            "standard_tier": required_plan in enabled_plans,
        }
        if required_plan in enabled_plans:
            evaluations.append(passed(RULE_ID, resource_id, _RESOURCE_TYPE, evidence))
            continue
        finding = build_finding(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            severity=SEVERITY,
            category=CATEGORY,
            resource_id=resource_id,
            resource_name=display_name,
            resource_type=_RESOURCE_TYPE,
            description=DESCRIPTION,
            remediation=REMEDIATION,
            playbook=PLAYBOOK,
            frameworks=FRAMEWORKS,
            scope="defender-plan-coverage",
            metadata={
                "required_defender_plans": sorted(policy.required_defender_plans),
                "plan_found_in_subscription": display_name in all_plan_names,
                "cis_control_reference": _CIS_PLAN_CONTROLS.get(required_plan, "N/A"),
                "permissions_required": ["Microsoft.Security/pricings/read"],
                "unknown_reason": None,
            },
        )
        evaluations.append(failed(RULE_ID, finding, evidence))
    return evaluations
