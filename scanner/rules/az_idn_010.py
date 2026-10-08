"""AZ-IDN-010: App Registration has no assigned owner."""

import logging
from typing import Any, Dict, List

from scanner.rules._identity_common import application_finding, application_identity

RULE_ID = "AZ-IDN-010"
RULE_NAME = "App Registration Has No Owner"
SEVERITY = "MEDIUM"
CATEGORY = "Identity"
FRAMEWORKS = {"CIS": "N/A-IDN-010", "NIST": "PR.AC-4", "ISO27001": "A.5.16", "SOC2": "CC6.2"}
DESCRIPTION = (
    "The App Registration has no assigned owner. Unowned applications can escape periodic review, "
    "credential rotation, permission cleanup, and accountable incident response."
)
REMEDIATION = "Assign at least one accountable owner and establish a periodic application ownership review."
PLAYBOOK = "playbooks/cli/fix_az_idn_010.sh"

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
        owners = application.get("owners")
        if owners is None:
            logger.warning("%s: owner state is unavailable for application %s", RULE_ID, object_id)
            continue
        if not owners:
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
                    metadata={"owner_count": 0},
                )
            )
    return findings
