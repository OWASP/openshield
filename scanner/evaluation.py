"""Rule evaluation contract (issue #263): per-resource coverage, not just findings.

``scan()`` only ever reports violations, so the absence of a finding is
indistinguishable from "compliant" and "never evaluated" — a rule that
errors out or hasn't been migrated yet silently reads as a pass. A rule
opts into this contract by additionally exposing::

    def evaluate(azure_client, subscription_id) -> List[RuleEvaluation]

which reports a status for every resource (or the subscription itself) it
looked at, PASS included. Rules that don't expose ``evaluate`` keep working
exactly as before via ``scan()``; the engine records their coverage as
UNKNOWN/LEGACY_RULE_NOT_MIGRATED instead of inventing a PASS.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Optional

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
