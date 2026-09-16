"""AZ-KV-006: Key Vault using legacy access policies instead of Azure RBAC."""

from typing import Any, Dict, List

from scanner.evaluation import EvaluationStatus, RuleEvaluation, subscription_scope_id

RULE_ID = "AZ-KV-006"
RULE_NAME = "Key Vault Using Legacy Access Policies Instead of Azure RBAC"
SEVERITY = "MEDIUM"
CATEGORY = "KeyVault"
FRAMEWORKS = {"CIS": "8.6", "NIST": "PR.AC-4", "ISO27001": "A.9.2.3", "SOC2": "CC6.1"}
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


def _finding(azure_client: Any, vault: Any) -> Dict[str, Any]:
    parsed = azure_client.parse_resource_id(vault.id)
    return {
        "rule_id": RULE_ID,
        "rule_name": RULE_NAME,
        "severity": SEVERITY,
        "category": CATEGORY,
        "resource_id": vault.id,
        "resource_name": vault.name,
        "resource_type": "Microsoft.KeyVault/vaults",
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
    findings: List[Dict[str, Any]] = []

    for vault in azure_client.get_key_vaults():
        props = getattr(vault, "properties", None)
        if props is None:
            continue

        # Access policies are the legacy default; a vault must opt into RBAC.
        rbac_enabled = getattr(props, "enable_rbac_authorization", False)
        if not rbac_enabled:
            findings.append(_finding(azure_client, vault))

    return findings


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report this rule's coverage: a status for every vault it looked at,
    PASS included, instead of only reporting violations via scan()."""
    vaults = azure_client.get_key_vaults()
    if not vaults:
        # AzureClient.get_key_vaults() returns [] both when there genuinely
        # are no vaults and when the list call itself failed — evaluate()
        # can't tell those apart on its own, so it reports NOT_APPLICABLE
        # rather than claiming a PASS it can't actually back up. Closing
        # that ambiguity with Azure Resource Graph is tracked separately.
        return [
            RuleEvaluation(
                rule_id=RULE_ID,
                resource_id=subscription_scope_id(subscription_id),
                resource_type="Microsoft.KeyVault/vaults",
                status=EvaluationStatus.NOT_APPLICABLE,
                reason_code="NO_RESOURCES_FOUND",
                reason="No Key Vaults were returned for this subscription.",
            )
        ]

    evaluations: List[RuleEvaluation] = []
    for vault in vaults:
        props = getattr(vault, "properties", None)
        if props is None:
            evaluations.append(
                RuleEvaluation(
                    rule_id=RULE_ID,
                    resource_id=vault.id,
                    resource_type="Microsoft.KeyVault/vaults",
                    status=EvaluationStatus.UNKNOWN,
                    reason_code="MISSING_PROPERTIES",
                    reason="Key Vault was returned without a properties payload.",
                )
            )
            continue

        rbac_enabled = getattr(props, "enable_rbac_authorization", False)
        if rbac_enabled:
            evaluations.append(
                RuleEvaluation(
                    rule_id=RULE_ID,
                    resource_id=vault.id,
                    resource_type="Microsoft.KeyVault/vaults",
                    status=EvaluationStatus.PASS,
                )
            )
        else:
            evaluations.append(
                RuleEvaluation(
                    rule_id=RULE_ID,
                    resource_id=vault.id,
                    resource_type="Microsoft.KeyVault/vaults",
                    status=EvaluationStatus.FAIL,
                    finding=_finding(azure_client, vault),
                )
            )

    return evaluations
