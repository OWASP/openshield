"""AZ-IDN-023: Identity Protection risk policies are disabled."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-IDN-023"
RULE_NAME = "Identity Protection Risk Policies Not Enabled"
SEVERITY = "MEDIUM"
CATEGORY = "Identity"
FRAMEWORKS = {
    "CIS": "N/A-IDN-023",
    "NIST": "DE.CM-3",
    "ISO27001": "A.12.4.1",
    "SOC2": "CC7.2",
}
DESCRIPTION = (
    "Microsoft Entra Identity Protection risk policies (user risk and sign-in risk) "
    "are not enabled. Risk policies automatically respond to detected anomalous "
    "activity — such as leaked credentials, impossible travel, or unfamiliar sign-in "
    "locations — by requiring MFA step-up or blocking access. Without these policies, "
    "compromised accounts and risky sign-ins proceed unimpeded until manually reviewed."
)
REMEDIATION = (
    "Enable both user risk and sign-in risk policies in Entra Identity Protection. "
    "In Entra ID: Security > Identity Protection > User risk policy: set User risk "
    "to High, require password change. Sign-in risk policy: set Sign-in risk to "
    "Medium and above, require MFA. Alternatively, configure equivalent risk-based "
    "Conditional Access policies which offer more granular control."
)
PLAYBOOK = "playbooks/cli/fix_az_idn_023.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    policies = azure_client.get_identity_protection_policies()
    if policies is None:
        logger.warning("%s: Identity Protection policy data unavailable", RULE_ID)
        return []

    user_risk = policies.get("userRiskPolicy") or {}
    sign_in_risk = policies.get("signInRiskPolicy") or {}

    if user_risk.get("isEnabled") and sign_in_risk.get("isEnabled"):
        return []

    disabled = []
    if not user_risk.get("isEnabled"):
        disabled.append("userRiskPolicy")
    if not sign_in_risk.get("isEnabled"):
        disabled.append("signInRiskPolicy")

    return [
        {
            "rule_id": RULE_ID,
            "rule_name": RULE_NAME,
            "severity": SEVERITY,
            "category": CATEGORY,
            "resource_id": f"/tenants/{subscription_id}/identityProtection",
            "resource_name": "Identity Protection Policies",
            "resource_type": "Microsoft.AzureActiveDirectory/identityProtectionPolicies",
            "description": DESCRIPTION,
            "remediation": REMEDIATION,
            "playbook": PLAYBOOK,
            "frameworks": FRAMEWORKS,
            "metadata": {
                "disabled_policies": disabled,
                "user_risk_enabled": user_risk.get("isEnabled", False),
                "sign_in_risk_enabled": sign_in_risk.get("isEnabled", False),
            },
        }
    ]
