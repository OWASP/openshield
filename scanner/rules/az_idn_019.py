"""AZ-IDN-019: Stale privileged account has not signed in for more than 90 days."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

RULE_ID = "AZ-IDN-019"
RULE_NAME = "Stale Privileged Account Retains Active Access"
SEVERITY = "HIGH"
CATEGORY = "Identity"
FRAMEWORKS = {
    "CIS": "N/A-IDN-019",
    "NIST": "PR.AC-1",
    "ISO27001": "A.9.2.5",
    "SOC2": "CC6.2",
}
DESCRIPTION = (
    "An enabled account holding a privileged directory role has not signed in for "
    "more than 90 days. Dormant privileged accounts represent a persistent attack "
    "surface. Credentials may be stale, MFA devices may be lost or reassigned, and "
    "the account may belong to a former employee who should no longer have access. "
    "An attacker who obtains these credentials gains unmonitored privileged access."
)
REMEDIATION = (
    "Review each stale privileged account and either confirm it is still required "
    "or disable and remove its role assignments. In Entra ID: Users > select the "
    "account > Block sign-in. Remove role assignments via Identity Governance > "
    "Privileged Identity Management or directly from the role membership. Implement "
    "a Conditional Access policy to enforce access reviews for privileged users at "
    "least every 90 days."
)
PLAYBOOK = "playbooks/cli/fix_az_idn_019.sh"

STALE_DAYS = 90

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    members = azure_client.get_privileged_role_members()
    if members is None:
        logger.warning("%s: privileged role member inventory unavailable", RULE_ID)
        return findings

    cutoff = datetime.now(timezone.utc) - timedelta(days=STALE_DAYS)

    for member in members:
        user_id = member.get("userId", "")
        if not user_id:
            continue
        if not member.get("accountEnabled", True):
            continue
        last_sign_in_raw = member.get("lastSignInDateTime")
        if last_sign_in_raw is None:
            # No sign-in record — treat as stale (never signed in)
            days_inactive = None
        else:
            try:
                last_sign_in = datetime.fromisoformat(last_sign_in_raw.replace("Z", "+00:00"))
                if last_sign_in >= cutoff:
                    continue
                days_inactive = (datetime.now(timezone.utc) - last_sign_in).days
            except (ValueError, AttributeError):
                days_inactive = None

        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": f"/users/{user_id}",
                "resource_name": member.get("userDisplayName", user_id),
                "resource_type": "Microsoft.Graph/users",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "user_principal_name": member.get("userPrincipalName", ""),
                    "role_name": member.get("roleName", ""),
                    "last_sign_in_datetime": last_sign_in_raw,
                    "days_inactive": days_inactive,
                },
            }
        )
    return findings
