"""AZ-STOR-003: Storage account has no lifecycle management policy configured."""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# subscription_id is received by scan() and passed to AzureClient methods
# that need explicit scope. It is not read from the environment here —
# the engine always passes it as a parameter. Never read os.environ directly.

# ── Required module-level constants ─────────────────────────────────────────

RULE_ID = "AZ-STOR-003"
RULE_NAME = "Storage Account Has No Lifecycle Management Policy"
SEVERITY = "MEDIUM"
CATEGORY = "Storage"
FRAMEWORKS = {
    "CIS": "3.7",
    "NIST": "PR.DS-3",
    "ISO27001": "A.7.10",
}
DESCRIPTION = (
    "The storage account has no lifecycle management policy configured. "
    "Without a lifecycle policy, blobs accumulate indefinitely — old data "
    "that is no longer needed remains accessible, increasing storage costs "
    "and the attack surface. A compromised account exposes all historical "
    "data with no automatic expiry or tiering in place."
)
REMEDIATION = (
    "Create a lifecycle management policy on the storage account that "
    "transitions blobs to cooler tiers (Cool, Archive) after a defined "
    "number of days, and deletes blobs that exceed the organisation's "
    "maximum retention period. Navigate to: Storage Account > "
    "Data management > Lifecycle management > Add a rule."
)
PLAYBOOK = "playbooks/cli/fix_az_stor_003.sh"


# ── Required scan function ───────────────────────────────────────────────────


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect storage accounts with no lifecycle management policy.

    The Azure Storage Management SDK exposes lifecycle policies via
    ``management_policies.get(resource_group, account_name)``.
    A ResourceNotFound (404) response means no policy exists — this is
    the condition we flag as MEDIUM severity.

    Three-state return from get_storage_lifecycle_policy():
        True  — policy exists and has rules → skip (compliant)
        False — no policy exists → create finding
        None  — permissions error or unexpected failure → skip with warning
                to avoid false positives

    Args:
        azure_client:    An AzureClient instance with all SDK clients
                         pre-configured.
        subscription_id: The Azure subscription ID being scanned.

    Returns:
        A list of finding dicts — one per storage account that has no
        lifecycle policy. Accounts that could not be checked are skipped
        and logged as warnings.
    """
    findings: List[Dict[str, Any]] = []

    for account in azure_client.get_storage_accounts():
        resource_id = getattr(account, "id", "")
        account_name = getattr(account, "name", "")
        location = getattr(account, "location", "")

        if not resource_id or not account_name:
            continue

        parsed = azure_client.parse_resource_id(resource_id)
        resource_group = parsed.get("resource_group", "")
        if not resource_group:
            continue

        # True = compliant, False = no policy, None = could not determine
        policy_status: Optional[bool] = azure_client.get_storage_lifecycle_policy(resource_group, account_name)

        if policy_status is None:
            # Permissions error or unexpected SDK failure.
            # Skip rather than flag — never create false positives.
            logger.warning(
                "AZ-STOR-003: Could not determine lifecycle policy for %s "
                "— skipping. Ensure the service principal has "
                "Microsoft.Storage/storageAccounts/managementPolicies/read "
                "permission.",
                account_name,
            )
            continue

        if policy_status is False:
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": resource_id,
                    "resource_name": account_name,
                    "resource_type": "Microsoft.Storage/storageAccounts",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "resource_group": resource_group,
                        "location": location,
                    },
                }
            )

    return findings
