"""AZ-IDN-014: Multi-tenant App Registration lacks application-instance property lock."""

import logging
from typing import Any, Dict, List

from scanner.rules._identity_common import application_finding, application_identity

RULE_ID = "AZ-IDN-014"
RULE_NAME = "Multi-Tenant App Registration Lacks Property Lock"
SEVERITY = "HIGH"
CATEGORY = "Identity"
FRAMEWORKS = {"CIS": "N/A-IDN-014", "NIST": "PR.IP-1", "ISO27001": "A.8.32", "SOC2": "CC6.6"}
DESCRIPTION = (
    "The multi-tenant App Registration does not lock all sensitive properties on its service-principal "
    "instances. Tenant administrators can modify credentials or token-encryption settings unexpectedly."
)
REMEDIATION = "Enable application-instance property lock and lock all sensitive service-principal properties."
PLAYBOOK = "playbooks/cli/fix_az_idn_014.sh"

logger = logging.getLogger(__name__)
_MULTI_TENANT_AUDIENCES = {"AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount"}


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    applications = azure_client.get_applications()
    if applications is None:
        logger.warning("%s: application inventory is unavailable", RULE_ID)
        return findings
    for application in applications:
        object_id, _ = application_identity(application)
        if not object_id or application.get("signInAudience") not in _MULTI_TENANT_AUDIENCES:
            continue
        lock = application.get("servicePrincipalLockConfiguration") or {}
        enabled = bool(lock.get("isEnabled", False))
        all_properties = bool(lock.get("allProperties", False))
        if not (enabled and all_properties):
            findings.append(
                application_finding(
                    application,
                    rule_id=RULE_ID,
                    rule_name=RULE_NAME,
                    severity=SEVERITY,
                    description=DESCRIPTION,
                    remediation=REMEDIATION,
                    playbook=PLAYBOOK,
                    frameworks=FRAMEWORKS,
                    metadata={
                        "sign_in_audience": application.get("signInAudience"),
                        "lock_enabled": enabled,
                        "all_sensitive_properties_locked": all_properties,
                    },
                )
            )
    return findings
