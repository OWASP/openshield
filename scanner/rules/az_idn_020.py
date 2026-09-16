"""AZ-IDN-020: Emergency access (break-glass) accounts missing or misconfigured."""

import logging
import re
from typing import Any, Dict, List

RULE_ID = "AZ-IDN-020"
RULE_NAME = "Emergency Access Accounts Missing or Incorrectly Configured"
SEVERITY = "HIGH"
CATEGORY = "Identity"
FRAMEWORKS = {
    "CIS": "N/A-IDN-020",
    "NIST": "PR.AC-4",
    "ISO27001": "A.9.1.2",
    "SOC2": "CC6.3",
}
DESCRIPTION = (
    "No emergency access (break-glass) Global Administrator accounts were detected "
    "in the tenant, or the detected accounts are misconfigured. Break-glass accounts "
    "are cloud-only, permanently assigned Global Administrator accounts used only when "
    "all other administrative access paths fail (e.g. MFA outage, Conditional Access "
    "misconfiguration). Without correctly configured break-glass accounts, an "
    "administrative lockout could make the tenant unrecoverable."
)
REMEDIATION = (
    "Create at least two cloud-only Global Administrator accounts with 'emergency', "
    "'breakglass', or 'break-glass' in the user principal name. Ensure each account: "
    "is cloud-only (not synced from on-premises); has a strong, randomly generated "
    "password stored in a physical safe; is excluded from all Conditional Access "
    "policies; has sign-in alerts configured; and its credentials are reviewed and "
    "rotated at least every 90 days. Document the accounts and their location in your "
    "incident response plan."
)
PLAYBOOK = "playbooks/cli/fix_az_idn_020.sh"

GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"
_BREAK_GLASS_PATTERN = re.compile(r"emergency|breakglass|break[-_]?glass", re.IGNORECASE)

logger = logging.getLogger(__name__)


def _is_break_glass(member: Dict[str, Any]) -> bool:
    upn = member.get("userPrincipalName", "")
    display = member.get("userDisplayName", "")
    return bool(_BREAK_GLASS_PATTERN.search(upn) or _BREAK_GLASS_PATTERN.search(display))


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    members = azure_client.get_privileged_role_members()
    if members is None:
        logger.warning("%s: privileged role member inventory unavailable", RULE_ID)
        return []

    global_admins = [m for m in members if m.get("roleId", "").lower() == GLOBAL_ADMIN_ROLE_ID]
    break_glass_accounts = [m for m in global_admins if _is_break_glass(m)]

    if len(break_glass_accounts) >= 2:
        return []

    return [
        {
            "rule_id": RULE_ID,
            "rule_name": RULE_NAME,
            "severity": SEVERITY,
            "category": CATEGORY,
            "resource_id": f"/tenants/{subscription_id}/emergencyAccess",
            "resource_name": "Emergency Access Accounts",
            "resource_type": "Microsoft.AzureActiveDirectory/emergencyAccess",
            "description": DESCRIPTION,
            "remediation": REMEDIATION,
            "playbook": PLAYBOOK,
            "frameworks": FRAMEWORKS,
            "metadata": {
                "break_glass_accounts_found": len(break_glass_accounts),
                "global_admin_count": len(global_admins),
                "minimum_required": 2,
            },
        }
    ]
