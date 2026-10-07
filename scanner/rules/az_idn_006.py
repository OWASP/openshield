"""AZ-IDN-006: Service principal client secret older than 90 days or with no expiry."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

RULE_ID = "AZ-IDN-006"
RULE_NAME = "Service Principal Client Secret Older Than 90 Days"
SEVERITY = "HIGH"
CATEGORY = "Identity"
FRAMEWORKS = {"CIS": "1.14", "NIST": "PR.AC-1", "ISO27001": "A.5.17", "SOC2": "CC6.1"}
DESCRIPTION = (
    "One or more service principal applications have client secrets with a creation "
    "date older than 90 days and no expiry date set, or secrets that have already "
    "expired but remain present. Long-lived or non-expiring secrets are a major "
    "credential hygiene risk. If a secret leaks it remains valid indefinitely, "
    "giving an attacker persistent access to the application and its permissions."
)
REMEDIATION = (
    "Rotate all client secrets older than 90 days and set an expiry date of no more "
    "than 90 days on new secrets. Run: az ad app credential reset --id <app-id> "
    "--years 0 --end-date <YYYY-MM-DD>. Consider migrating to certificate-based "
    "authentication or managed identities to eliminate secret rotation entirely."
)
PLAYBOOK = "playbooks/cli/fix_az_idn_006.sh"

logger = logging.getLogger(__name__)

EXPIRY_THRESHOLD_DAYS = 90


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect service principals with stale or non-expiring client secrets."""
    findings: List[Dict[str, Any]] = []

    applications = azure_client.get_applications()
    if applications is None:
        logger.error("AZ-IDN-006: Application inventory is unavailable")
        logger.warning(
            "AZ-IDN-006: Ensure the service principal has Application.Read.All permission on Microsoft Graph."
        )
        return findings

    now = datetime.now(timezone.utc)

    for app in applications:
        app_id = app.get("id", "")
        app_display_name = app.get("displayName", app.get("appId", app_id))

        for cred in app.get("passwordCredentials", []):
            start_dt_str = cred.get("startDateTime")
            end_dt_str = cred.get("endDateTime")
            key_id = cred.get("keyId", "")
            hint = cred.get("hint", "")

            if not start_dt_str:
                continue

            try:
                start_dt = datetime.fromisoformat(start_dt_str.replace("Z", "+00:00"))
            except ValueError:
                continue

            age_days = (now - start_dt).days
            no_expiry = end_dt_str is None
            already_expired = False

            if end_dt_str:
                try:
                    end_dt = datetime.fromisoformat(end_dt_str.replace("Z", "+00:00"))
                    already_expired = end_dt < now
                except ValueError:
                    logger.debug(
                        "AZ-IDN-006: Invalid endDateTime format for app_id=%s",
                        app_id,
                    )

            if not (age_days >= EXPIRY_THRESHOLD_DAYS or no_expiry or already_expired):
                continue

            if no_expiry:
                reason = "no expiry date set"
            elif already_expired:
                reason = "secret has expired but is still present"
            else:
                reason = f"secret is {age_days} days old (threshold: {EXPIRY_THRESHOLD_DAYS} days)"

            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": (f"/applications/{app_id}/passwordCredentials/{key_id}"),
                    "resource_name": app_display_name,
                    "resource_type": "Microsoft.Graph/applications",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "app_id": app_id,
                        "app_client_id": app.get("appId", ""),
                        "credential_hint": hint,
                        "credential_key_id": key_id,
                        "age_days": age_days,
                        "no_expiry": no_expiry,
                        "already_expired": already_expired,
                        "reason": reason,
                    },
                }
            )

    return findings
