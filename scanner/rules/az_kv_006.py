"""AZ-KV-006: Key Vault using legacy access policies instead of Azure RBAC."""

from typing import Any, Dict, List

from scanner.evaluation import (
    MISSING_PROPERTIES,
    EvaluationStatus,
    RuleEvaluation,
    fail_findings,
    inventory_unavailable,
    no_resources_found,
)

RULE_ID = "AZ-KV-006"
RULE_NAME = "Key Vault Using Legacy Access Policies Instead of Azure RBAC"
SEVERITY = "MEDIUM"
CATEGORY = "KeyVault"
FRAMEWORKS = {"CIS": "8.6", "NIST": "PR.AC-4", "ISO27001": "A.8.2", "SOC2": "CC6.1"}
DESCRIPTION = (
    "The Azure Key Vault is authorizing access through legacy vault access policies "
    "instead of Azure RBAC. Access policies are all-or-nothing per permission type, "
    "cannot be scoped to individual keys/secrets/certificates, are not covered by "
    "Azure RBAC's centralized audit trail (Activity Log role assignments), and are "
    "easy to over-grant since there is no built-in least-privilege role model."
)
REMEDIATION = (
    "Enable Azure RBAC authorization on the Key Vault and replace access policies "
    "with scoped role assignments (e.g. Key Vault Secrets User, Key Vault Crypto Officer). "
    "Note: switching to RBAC does not delete existing access policies, but they stop being enforced."
)
PLAYBOOK = "playbooks/cli/fix_az_kv_006.sh"
RESOURCE_TYPE = "Microsoft.KeyVault/vaults"


def _finding(azure_client: Any, vault: Any) -> Dict[str, Any]:
    parsed = azure_client.parse_resource_id(vault.id)
    return {
        "rule_id": RULE_ID,
        "rule_name": RULE_NAME,
        "severity": SEVERITY,
        "category": CATEGORY,
        "resource_id": vault.id,
        "resource_name": vault.name,
        "resource_type": RESOURCE_TYPE,
        "description": DESCRIPTION,
        "remediation": REMEDIATION,
        "playbook": PLAYBOOK,
        "frameworks": FRAMEWORKS,
        "metadata": {
            "resource_group": parsed.get("resource_group", ""),
            "location": getattr(vault, "location", ""),
        },
    }


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect Key Vaults where enable_rbac_authorization is False or None."""
    return fail_findings(evaluate(azure_client, subscription_id))


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report this rule's coverage: a status for every vault it looked at,
    PASS included, instead of only reporting violations."""
    vaults = azure_client.list_key_vaults()
    if vaults is None:
        return [inventory_unavailable(RULE_ID, RESOURCE_TYPE, subscription_id)]
    if not vaults:
        return [no_resources_found(RULE_ID, RESOURCE_TYPE, subscription_id)]

    evaluations: List[RuleEvaluation] = []
    for vault in vaults:
        props = getattr(vault, "properties", None)
        if props is None:
            evaluations.append(
                RuleEvaluation(
                    rule_id=RULE_ID,
                    resource_id=vault.id,
                    resource_type=RESOURCE_TYPE,
                    status=EvaluationStatus.UNKNOWN,
                    reason_code=MISSING_PROPERTIES,
                    reason="Key Vault was returned without a properties payload.",
                )
            )
            continue

        # Access policies are the legacy default; a vault must opt into RBAC.
        rbac_enabled = getattr(props, "enable_rbac_authorization", False)
        evidence = {"enable_rbac_authorization": rbac_enabled}
        if rbac_enabled:
            evaluations.append(
                RuleEvaluation(
                    rule_id=RULE_ID,
                    resource_id=vault.id,
                    resource_type=RESOURCE_TYPE,
                    status=EvaluationStatus.PASS,
                    evidence=evidence,
                )
            )
        else:
            evaluations.append(
                RuleEvaluation(
                    rule_id=RULE_ID,
                    resource_id=vault.id,
                    resource_type=RESOURCE_TYPE,
                    status=EvaluationStatus.FAIL,
                    evidence=evidence,
                    finding=_finding(azure_client, vault),
                )
            )

    return evaluations
