"""AZ-IDN-011: App Registration contains an insecure HTTP redirect URI."""

import ipaddress
import logging
from typing import Any, Dict, Iterable, List, Mapping
from urllib.parse import urlparse

from scanner.rules._identity_common import application_finding, application_identity

RULE_ID = "AZ-IDN-011"
RULE_NAME = "App Registration Uses Insecure Redirect URI"
SEVERITY = "HIGH"
CATEGORY = "Identity"
FRAMEWORKS = {"CIS": "N/A-IDN-011", "NIST": "PR.DS-2", "ISO27001": "A.8.26", "SOC2": "CC6.7"}
DESCRIPTION = (
    "The App Registration contains an HTTP redirect URI for a non-loopback host. Authorization "
    "responses can be intercepted or modified before reaching the application."
)
REMEDIATION = "Replace non-loopback HTTP redirect URIs with exact HTTPS URIs and remove obsolete entries."
PLAYBOOK = "playbooks/cli/fix_az_idn_011.sh"

logger = logging.getLogger(__name__)


def _redirect_uris(application: Mapping[str, Any]) -> Iterable[str]:
    for profile_name in ("web", "spa", "publicClient"):
        profile = application.get(profile_name) or {}
        for uri in profile.get("redirectUris", []) or []:
            if isinstance(uri, str):
                yield uri


def _is_loopback(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _is_insecure_http_redirect(uri: str) -> bool:
    parsed = urlparse(uri)
    if parsed.scheme.lower() != "http":
        return False
    return not parsed.hostname or not _is_loopback(parsed.hostname)


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
        insecure_uris = [uri for uri in _redirect_uris(application) if _is_insecure_http_redirect(uri)]
        if insecure_uris:
            schemes = sorted({urlparse(uri).scheme.lower() for uri in insecure_uris})
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
                    metadata={"insecure_redirect_count": len(insecure_uris), "schemes": schemes},
                )
            )
    return findings
