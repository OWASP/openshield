"""AZ-SECOPS-007: A high-risk Defender recommendation remains unresolved beyond its SLA."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from scanner.evaluation import (
    MISSING_PROPERTIES,
    EvaluationStatus,
    RuleEvaluation,
    fail_findings,
    subscription_scope_id,
)
from scanner.rules._security_operations_common import (
    build_collector,
    build_finding,
    collection_failed,
    failed,
    is_usable,
    passed,
    prepare,
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
_RESOURCE_TYPE = "Microsoft.Security/assessments"

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


def _finding(
    assessment: Any, resource_id: str, first_observed: datetime, age_days: int, sla_days: int
) -> Dict[str, Any]:
    return build_finding(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity=SEVERITY,
        category=CATEGORY,
        resource_id=resource_id,
        resource_name=_display_name(assessment),
        resource_type=_RESOURCE_TYPE,
        description=DESCRIPTION,
        remediation=REMEDIATION,
        playbook=PLAYBOOK,
        frameworks=FRAMEWORKS,
        scope="defender-recommendation-sla",
        metadata={
            "severity_source": "High",
            "status": "Unhealthy",
            "age_days": age_days,
            "sla_days": sla_days,
            "first_observed": first_observed.isoformat(),
            "permissions_required": ["Microsoft.Security/assessments/read"],
            "unknown_reason": None,
        },
    )


def _missing(resource_id: str, reason: str) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=RULE_ID,
        resource_id=resource_id,
        resource_type=_RESOURCE_TYPE,
        status=EvaluationStatus.UNKNOWN,
        reason_code=MISSING_PROPERTIES,
        reason=reason,
    )


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Return the findings attached to this rule's FAIL evaluations."""
    return fail_findings(evaluate(azure_client, subscription_id))


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report, per affected resource, whether its unresolved High-severity recommendations are within SLA.

    Evaluations are grouped by affected resource so one resource never gets
    two rows: FAIL when any of its recommendations is past the SLA (the
    finding describes the oldest), UNKNOWN when one has no usable timestamp,
    otherwise PASS. With no unresolved High-severity recommendation at all,
    the subscription is PASS.
    """
    collector, policy, early = prepare(RULE_ID, _RESOURCE_TYPE, azure_client, subscription_id, build_collector)
    if early is not None:
        return early

    result = collector.defender_assessments()
    if not is_usable(result):
        return [collection_failed(RULE_ID, _RESOURCE_TYPE, subscription_id, result)]

    now = datetime.now(timezone.utc)
    sla_days = policy.defender_recommendation_sla_days
    by_resource: Dict[str, List[Tuple[Any, Optional[datetime], Optional[int]]]] = {}
    unidentified = 0
    for assessment in result.items:
        if _severity(assessment) not in _HIGH_SEVERITY or _status_code(assessment) not in _UNHEALTHY:
            continue
        resource_details = value(assessment, "resource_details")
        resource_id = str(value(resource_details, "id") or value(assessment, "id") or "")
        if not resource_id:
            unidentified += 1
            continue
        first_observed = _first_observed(assessment)
        age_days = None
        if first_observed is not None:
            if first_observed.tzinfo is None:
                first_observed = first_observed.replace(tzinfo=timezone.utc)
            age_days = (now - first_observed).days
        by_resource.setdefault(resource_id, []).append((assessment, first_observed, age_days))

    evaluations: List[RuleEvaluation] = []
    if unidentified:
        evaluations.append(
            _missing(
                # Not the subscription ID itself: a subscription-level
                # assessment is keyed on that and must keep its own row.
                f"{subscription_scope_id(subscription_id)}/providers/Microsoft.Security/assessments",
                f"{unidentified} unresolved High-severity recommendation(s) were returned without a resource ID.",
            )
        )
    if not by_resource:
        if not evaluations:
            evaluations.append(
                passed(
                    RULE_ID,
                    subscription_scope_id(subscription_id),
                    _RESOURCE_TYPE,
                    {"unresolved_high_severity": 0, "sla_days": sla_days},
                )
            )
        return evaluations

    for resource_id, entries in by_resource.items():
        overdue = [entry for entry in entries if entry[2] is not None and entry[2] > sla_days]
        undated = [entry for entry in entries if entry[2] is None]
        evidence = {
            "unresolved_high_severity": len(entries),
            "overdue": len(overdue),
            "without_timestamp": len(undated),
            "sla_days": sla_days,
        }
        if overdue:
            assessment, first_observed, age_days = max(overdue, key=lambda entry: entry[2])
            finding = _finding(assessment, resource_id, first_observed, age_days, sla_days)
            if len(overdue) > 1:
                finding["metadata"]["overdue_recommendations"] = [
                    {"name": _display_name(entry[0]), "age_days": entry[2]} for entry in overdue
                ]
            evaluations.append(failed(RULE_ID, finding, evidence))
        elif undated:
            evaluations.append(
                _missing(
                    resource_id, "An unresolved High-severity recommendation has no usable first-observed timestamp."
                )
            )
        else:
            evaluations.append(passed(RULE_ID, resource_id, _RESOURCE_TYPE, evidence))
    return evaluations
