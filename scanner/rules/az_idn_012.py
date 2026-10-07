"""AZ-IDN-012: App Registration enables OAuth implicit grant."""

import logging
from typing import Any, Dict, List

from scanner.rules._identity_common import application_finding, application_identity

RULE_ID = "AZ-IDN-012"
RULE_NAME = "App Registration Enables OAuth Implicit Grant"
SEVERITY = "MEDIUM"
CATEGORY = "Identity"
FRAMEWORKS = {"CIS": "N/A-IDN-012", "NIST": "PR.AC-3", "ISO27001": "A.8.5", "SOC2": "CC6.1"}
DESCRIPTION = (
    "The App Registration enables access-token or ID-token issuance through the legacy implicit "
    "grant flow. Tokens can be exposed to browser history, extensions, or front-channel leakage."
)
REMEDIATION = "Disable implicit grant and migrate clients to authorization code flow with PKCE."
PLAYBOOK = "playbooks/cli/fix_az_idn_012.sh"

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
        settings = (application.get("web") or {}).get("implicitGrantSettings") or {}
        access_tokens = bool(settings.get("enableAccessTokenIssuance", False))
        id_tokens = bool(settings.get("enableIdTokenIssuance", False))
        if access_tokens or id_tokens:
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
                    metadata={"access_token_issuance": access_tokens, "id_token_issuance": id_tokens},
                )
            )
    return findings
