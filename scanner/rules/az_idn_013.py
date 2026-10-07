"""AZ-IDN-013: App Registration uses password credentials."""

import logging
from typing import Any, Dict, List

from scanner.rules._identity_common import application_finding, application_identity

RULE_ID = "AZ-IDN-013"
RULE_NAME = "App Registration Uses Password Credentials"
SEVERITY = "MEDIUM"
CATEGORY = "Identity"
FRAMEWORKS = {"CIS": "N/A-IDN-013", "NIST": "PR.AC-1", "ISO27001": "A.5.17", "SOC2": "CC6.1"}
DESCRIPTION = (
    "The App Registration has one or more password credentials. Client secrets are commonly copied, "
    "logged, leaked, or left unrotated and are weaker than managed identity or certificate authentication."
)
REMEDIATION = "Migrate to managed identity, workload identity federation, or certificates, then remove client secrets."
PLAYBOOK = "playbooks/cli/fix_az_idn_013.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    applications = azure_client.get_applications()
    if applications is None:
        logger.warning("%s: application inventory is unavailable", RULE_ID)
        return findings
    for application in applications:
        object_id, _ = application_identity(application)
        if not object_id:
            continue
        password_credentials = application.get("passwordCredentials") or []
        if password_credentials:
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
                        "password_credential_count": len(password_credentials),
                        "certificate_credential_count": len(application.get("keyCredentials") or []),
                    },
                )
            )
    return findings
