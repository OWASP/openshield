"""AZ-SECOPS-007: A high-risk Defender recommendation remains unresolved beyond its SLA."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from scanner.rules._security_operations_common import (
    build_collector,
    build_finding,
    is_usable,
    load_policy_from_env,
    value,
)

logger = logging.getLogger(__name__)

RULE_ID = "AZ-SECOPS-007"
RULE_NAME = "High-Risk Defender Recommendation Unresolved Beyond SLA"
SEVERITY = "HIGH"
CATEGORY = "Security Operations"
FRAMEWORKS = {"CIS": "2.1.13", "NIST": "RS.MI-3", "ISO27001": "A.8.8", "SOC2": "CC7.1"}
DESCRIPTION = (
    "A Microsoft Defender for Cloud security assessment with High severity is Unhealthy and has "
    "remained unresolved longer than the organisation's remediation SLA. The Defender assessment "
    "API does not return a typed first-observed timestamp; the age used here is read from the "
    "assessment's non-secret additional_data map when the resource provider populates a recognised "
    "timestamp key. When no such timestamp is available the assessment's age cannot be determined "
    "and it is excluded from this rule's findings (never assumed to be either compliant or overdue)."
)
REMEDIATION = (
    "Review and remediate the Defender recommendation before its SLA expires:\n"
    "  az security assessment show --name <assessment-name>\n"
    "Address the underlying resource misconfiguration described by the recommendation, or record "
    "an approved risk-acceptance exception with the security team if remediation is not currently possible."
)
PLAYBOOK = "playbooks/cli/fix_az_secops_007.sh"

_HIGH_SEVERITY = {"high"}
_UNHEALTHY = {"unhealthy"}

# Recognised keys the Defender assessment API has been observed to populate in
# additional_data for a first-evaluation/first-detected timestamp. Not a
# formal SDK contract (additional_data is Dict[str, str]); read defensively.
_TIMESTAMP_KEYS = ("firstEvaluationDate", "firstEvaluationTime", "timeGenerated", "detectedTimeUtc")


def _severity(assessment: Any) -> str:
    metadata = value(assessment, "metadata")
    sev = value(metadata, "severity")
    return str(getattr(sev, "value", sev) or "").strip().lower()


def _status_code(assessment: Any) -> str:
    status = value(assessment, "status")
    code = value(status, "code")
    return str(getattr(code, "value", code) or "").strip().lower()


def _display_name(assessment: Any) -> str:
    metadata = value(assessment, "metadata")
    return str(value(metadata, "display_name") or value(assessment, "name") or "Defender recommendation")


def _first_observed(assessment: Any) -> Optional[datetime]:
    additional_data = value(assessment, "additional_data") or {}
    if not isinstance(additional_data, dict):
        return None
    for key in _TIMESTAMP_KEYS:
        raw = additional_data.get(key)
        if not raw:
            continue
        try:
            return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            continue
    return None


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Flag unresolved High-severity Defender assessments older than the SLA."""
    policy = load_policy_from_env(RULE_ID)
    if policy is None:
        return []

    collector = build_collector(azure_client, subscription_id)
    result = collector.defender_assessments()
    if not is_usable(result):
        logger.warning("%s: Defender assessments unavailable (%s); result is UNKNOWN", RULE_ID, result.error_code)
        return []

    now = datetime.now(timezone.utc)
    findings: List[Dict[str, Any]] = []
    for assessment in result.items:
        if _severity(assessment) not in _HIGH_SEVERITY or _status_code(assessment) not in _UNHEALTHY:
            continue
        first_observed = _first_observed(assessment)
        if first_observed is None:
            logger.info(
                "%s: assessment %s has no usable first-observed timestamp; age is UNKNOWN, skipped",
                RULE_ID,
                _display_name(assessment),
            )
            continue
        if first_observed.tzinfo is None:
            first_observed = first_observed.replace(tzinfo=timezone.utc)
        age_days = (now - first_observed).days
        if age_days <= policy.defender_recommendation_sla_days:
            continue

        resource_details = value(assessment, "resource_details")
        resource_id = str(value(resource_details, "id") or value(assessment, "id") or "")
        findings.append(
            build_finding(
                rule_id=RULE_ID,
                rule_name=RULE_NAME,
                severity=SEVERITY,
                category=CATEGORY,
                resource_id=resource_id or str(value(assessment, "id") or ""),
                resource_name=_display_name(assessment),
                resource_type="Microsoft.Security/assessments",
                description=DESCRIPTION,
                remediation=REMEDIATION,
                playbook=PLAYBOOK,
                frameworks=FRAMEWORKS,
                scope="defender-recommendation-sla",
                metadata={
                    "severity_source": "High",
                    "status": "Unhealthy",
                    "age_days": age_days,
                    "sla_days": policy.defender_recommendation_sla_days,
                    "first_observed": first_observed.isoformat(),
                    "permissions_required": ["Microsoft.Security/assessments/read"],
                    "unknown_reason": None,
                },
            )
        )
    return findings
