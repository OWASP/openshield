"""Rule evaluation contract (issue #263): per-resource coverage, not just findings.

``scan()`` only ever reports violations, so the absence of a finding is
indistinguishable from "compliant" and "never evaluated" — a rule that
errors out or hasn't been migrated yet silently reads as a pass. A rule
opts into this contract by additionally exposing::

    def evaluate(azure_client, subscription_id) -> List[RuleEvaluation]

which reports a status for every resource (or the subscription itself) it
looked at, PASS included. When a rule exposes ``evaluate``, the engine runs
it instead of ``scan()`` and takes findings from its FAIL evaluations; a
migrated rule keeps ``scan()`` as a thin wrapper over ``fail_findings()``.
Rules that don't expose ``evaluate`` keep working exactly as before via
``scan()``; the engine records their coverage as
UNKNOWN/LEGACY_RULE_NOT_MIGRATED instead of inventing a PASS.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

# Conservative rank: worse coverage information must never be hidden by
# better information rolled up from a different resource under the same rule.
_AGGREGATE_ORDER = ("FAIL", "ERROR", "UNKNOWN", "PASS", "NOT_APPLICABLE")
_RANK = {status: i for i, status in enumerate(_AGGREGATE_ORDER)}

STATUSES = frozenset(_AGGREGATE_ORDER)
_REASON_REQUIRED = frozenset({"UNKNOWN", "ERROR", "NOT_APPLICABLE"})


class EvaluationStatus:
    """Canonical evaluation outcomes. Plain string constants, not an enum
    class, so a status can be stored/compared as the same string Postgres's
    CHECK constraint enforces."""

    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"
    NOT_APPLICABLE = "NOT_APPLICABLE"


def subscription_scope_id(subscription_id: str) -> str:
    """Canonical non-empty resource_id for a subscription/rule-level result.

    Used whenever an evaluation isn't about one specific resource (a legacy
    rule's placeholder, an evaluator exception with no resource to blame).
    Never an empty string — that would collide across rules/subscriptions.
    """
    return f"/subscriptions/{subscription_id}"


# Standard reason codes shared across rule families, so the same situation
# reads the same way in every compliance report:
#
#   INVENTORY_UNAVAILABLE  ERROR           the resource list call failed
#   NO_RESOURCES_FOUND     NOT_APPLICABLE  the list call succeeded but was empty
#   EVIDENCE_UNAVAILABLE   UNKNOWN         a per-resource lookup returned None
#   MISSING_PROPERTIES     UNKNOWN         the resource lacked a required field
#   POLICY_NOT_REQUIRED    NOT_APPLICABLE  opt-in policy tag not set
#   APPROVED_EXCEPTION     NOT_APPLICABLE  approved exception tag set
#
# ERROR indicates unavailable evaluation evidence. The scan-level
# ``failed_rule_ids`` list is stricter: partial ERROR rows do not fail a rule
# if it also returned usable outcomes, but a rule with only ERROR rows has no
# usable coverage and is listed as failed. A per-resource evidence gap should
# normally be UNKNOWN, not ERROR.
INVENTORY_UNAVAILABLE = "INVENTORY_UNAVAILABLE"
NO_RESOURCES_FOUND = "NO_RESOURCES_FOUND"
EVIDENCE_UNAVAILABLE = "EVIDENCE_UNAVAILABLE"
MISSING_PROPERTIES = "MISSING_PROPERTIES"
POLICY_NOT_REQUIRED = "POLICY_NOT_REQUIRED"
APPROVED_EXCEPTION = "APPROVED_EXCEPTION"


@dataclass
class RuleEvaluation:
    """One rule's coverage statement about one resource (or the subscription)."""

    rule_id: str
    resource_id: str
    resource_type: str
    status: str
    reason_code: Optional[str] = None
    reason: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    finding: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"unsupported evaluation status: {self.status!r}")
        if not self.resource_id:
            raise ValueError("RuleEvaluation.resource_id must be a non-empty canonical identifier")
        if self.status in _REASON_REQUIRED and not self.reason_code:
            raise ValueError(f"status {self.status} requires a reason_code")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "status": self.status,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "evidence": self.evidence,
        }


def aggregate_status(statuses: Iterable[str]) -> str:
    """Roll up several resource-level statuses for one rule into one status.

    FAIL beats ERROR beats UNKNOWN beats PASS beats NOT_APPLICABLE, so a
    single bad resource (or a single evaluator failure) can never be
    outvoted by resources that happened to pass.
    """
    best = None
    for status in statuses:
        if best is None or _RANK[status] < _RANK[best]:
            best = status
    if best is None:
        raise ValueError("aggregate_status requires at least one status")
    return best


def inventory_unavailable(rule_id: str, resource_type: str, subscription_id: str) -> "RuleEvaluation":
    """ERROR for a rule whose resource list call failed (inventory returned None).

    A failed list must never read as PASS or NOT_APPLICABLE: the rule did not
    get to look at anything.
    """
    return RuleEvaluation(
        rule_id=rule_id,
        resource_id=subscription_scope_id(subscription_id),
        resource_type=resource_type,
        status=EvaluationStatus.ERROR,
        reason_code=INVENTORY_UNAVAILABLE,
        reason=f"The {resource_type} inventory could not be read for this subscription.",
    )


def no_resources_found(rule_id: str, resource_type: str, subscription_id: str) -> "RuleEvaluation":
    """NOT_APPLICABLE for a rule whose list call succeeded but returned nothing."""
    return RuleEvaluation(
        rule_id=rule_id,
        resource_id=subscription_scope_id(subscription_id),
        resource_type=resource_type,
        status=EvaluationStatus.NOT_APPLICABLE,
        reason_code=NO_RESOURCES_FOUND,
        reason=f"No {resource_type} resources were returned for this subscription.",
    )


def fail_findings(evaluations: Iterable["RuleEvaluation"]) -> List[Dict[str, Any]]:
    """Findings attached to FAIL evaluations, for a migrated rule's scan() wrapper."""
    return [e.finding for e in evaluations if e.status == EvaluationStatus.FAIL and e.finding]
