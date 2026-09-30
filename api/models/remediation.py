"""Approval, idempotency, audit and rescan gate for agent-driven remediation (issue #266).

Running a ``playbooks/cli`` script against a real subscription has real blast
radius: a bad proposal or a retry can change customer infrastructure. This
module is the gate every execution-adjacent path must go through. It is
deliberately narrow: it records proposals, enforces who may advance them, and
decides whether a remediation actually worked. It never runs a playbook.

Lifecycle::

    PROPOSED -> APPROVED -> EXECUTING -> PENDING_VERIFICATION -> VERIFIED
        |           |           |                  |
        |           |           v                  v
        |           |     EXECUTION_FAILED   VERIFICATION_FAILED
        v           v
     REJECTED    REJECTED

Guarantees, each enforced by a single conditional ``UPDATE`` or a database
constraint rather than a check-then-write in Python:

* **Approval is mandatory.** ``begin_execution`` only matches ``APPROVED`` rows.
* **Nothing runs twice.** ``APPROVED -> EXECUTING`` can be won by exactly one
  caller. A crash mid-execution leaves the row ``EXECUTING`` and it is never
  retried automatically: at-most-once, because an unknown outcome on customer
  infrastructure needs a human, not a second attempt.
* **Nothing runs unless allowlisted.** ``EXECUTION_ALLOWLIST`` starts empty.
* **Approval is race-free.** Two concurrent approvals of one ``PROPOSED`` row
  cannot both transition it; the loser is told the row already moved on.
* **One live action per finding.** A partial unique index backs ``propose``.
* **Done means rescanned.** ``VERIFIED`` requires a later completed scan whose
  rule evaluation for the same resource is ``PASS``. A missing, ``UNKNOWN`` or
  ``ERROR`` result is inconclusive and leaves the action open, and a ``FAIL``
  moves it to ``VERIFICATION_FAILED``. Neither closes the finding.
* **Every step is audited** in an append-only table, in the same transaction
  as the state change it describes.
"""

import json
import logging
import uuid
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Tuple

import psycopg2.extras

from api.models.finding import DatabaseManager
from scanner.evaluation import EvaluationStatus, subscription_scope_id

logger = logging.getLogger(__name__)

PROPOSED = "PROPOSED"
APPROVED = "APPROVED"
EXECUTING = "EXECUTING"
EXECUTION_FAILED = "EXECUTION_FAILED"
PENDING_VERIFICATION = "PENDING_VERIFICATION"
VERIFICATION_FAILED = "VERIFICATION_FAILED"
VERIFIED = "VERIFIED"
REJECTED = "REJECTED"

# Statuses that keep a finding locked to its action. Mirrors the partial unique
# index in migration b6d2f8a4c1e7.
OPEN_STATUSES: FrozenSet[str] = frozenset(
    {PROPOSED, APPROVED, EXECUTING, EXECUTION_FAILED, PENDING_VERIFICATION, VERIFICATION_FAILED}
)
_REJECTABLE = (PROPOSED, APPROVED, EXECUTION_FAILED, VERIFICATION_FAILED)
_VERIFIABLE = (PENDING_VERIFICATION, VERIFICATION_FAILED)

# Playbooks eligible for any automated execution. Empty on purpose: phase one
# ships proposal generation only. Adding an entry is a reviewed code change, not
# configuration, so the set of things an agent may ever run stays auditable.
EXECUTION_ALLOWLIST: FrozenSet[str] = frozenset()


class RemediationError(RuntimeError):
    """Base class for gate refusals."""


class RemediationNotFound(RemediationError):
    """The finding or action does not exist."""


class InvalidTransition(RemediationError):
    """The action is not in a state that permits the requested step."""

    def __init__(self, action_id: str, requested: str, current: str) -> None:
        super().__init__(f"Action {action_id} cannot {requested} from status {current}")
        self.action_id = action_id
        self.requested = requested
        self.current = current


class NotAllowlisted(RemediationError):
    """The playbook is not eligible for automated execution."""


def _require_actor(actor: str, role: str) -> str:
    actor = (actor or "").strip()
    if not actor:
        raise ValueError(f"{role} identity is required")
    return actor


class RemediationGate:
    """Durable state machine for remediation actions, backed by PostgreSQL."""

    def __init__(self, db: DatabaseManager, allowlist: Optional[Iterable[str]] = None) -> None:
        self._db = db
        self._allowlist: FrozenSet[str] = EXECUTION_ALLOWLIST if allowlist is None else frozenset(allowlist)

    def is_allowlisted(self, playbook: str) -> bool:
        return playbook in self._allowlist

    # ------------------------------------------------------------------ #
    # Internals                                                             #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _audit(
        cur: Any,
        action_id: str,
        event: str,
        actor: str,
        from_status: Optional[str],
        to_status: Optional[str],
        detail: Optional[Dict[str, Any]] = None,
    ) -> None:
        cur.execute(
            """
            INSERT INTO remediation_audit_log (action_id, event, from_status, to_status, actor, detail)
            VALUES (%s, %s, %s, %s, %s, %s::jsonb)
            """,
            (action_id, event, from_status, to_status, actor, json.dumps(detail or {}, default=str)),
        )

    @staticmethod
    def _current_status(cur: Any, action_id: str) -> str:
        cur.execute("SELECT status FROM remediation_actions WHERE action_id = %s", (action_id,))
        row = cur.fetchone()
        if row is None:
            raise RemediationNotFound(f"Remediation action {action_id} not found")
        return row["status"]

    def _transition(
        self,
        action_id: str,
        *,
        event: str,
        actor: str,
        from_statuses: Tuple[str, ...],
        to_status: str,
        assignments: str = "",
        params: Tuple[Any, ...] = (),
        extra_where: str = "",
        where_params: Tuple[Any, ...] = (),
        detail: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Move one action between statuses atomically and audit it.

        The ``WHERE status = ANY(...)`` clause is the entire concurrency
        control: of any number of simultaneous callers exactly one matches the
        row, and the rest see zero rows updated.
        """
        conn = self._db._get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # FOR UPDATE in the CTE captures the status this caller is
                # replacing, so the audit row records the real predecessor when
                # several source statuses are allowed.
                cur.execute(
                    f"""
                    WITH old AS (
                        SELECT action_id, status FROM remediation_actions WHERE action_id = %s FOR UPDATE
                    )
                    UPDATE remediation_actions AS a
                    SET status = %s, updated_at = CURRENT_TIMESTAMP{assignments}
                    FROM old
                    WHERE a.action_id = old.action_id AND a.status = ANY(%s){extra_where}
                    RETURNING a.*, old.status AS previous_status
                    """,
                    (action_id, to_status, *params, list(from_statuses), *where_params),
                )
                row = cur.fetchone()
                if row is None:
                    current = self._current_status(cur, action_id)
                    conn.rollback()
                    raise InvalidTransition(action_id, event, current)
                row = dict(row)
                previous = row.pop("previous_status")
                self._audit(cur, action_id, event, actor, previous, to_status, detail)
            conn.commit()
            return row
        except Exception:
            self._db.rollback(conn)
            raise

    # ------------------------------------------------------------------ #
    # Steps                                                                 #
    # ------------------------------------------------------------------ #

    def propose(self, finding_id: int, proposed_by: str) -> Tuple[Dict[str, Any], str]:
        """Record a proposal for a finding's playbook.

        Returns ``(action, outcome)`` where outcome is ``created`` or
        ``existing``. A finding has at most one live action, so a retried or
        concurrent proposal converges on the same row instead of duplicating it.
        """
        proposed_by = _require_actor(proposed_by, "Proposer")
        conn = self._db._get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT id, playbook FROM findings WHERE id = %s", (finding_id,))
                finding = cur.fetchone()
                if finding is None:
                    raise RemediationNotFound(f"Finding {finding_id} not found")
                playbook = (finding["playbook"] or "").strip()
                if not playbook:
                    raise RemediationError(f"Finding {finding_id} has no playbook to propose")

                open_statuses = sorted(OPEN_STATUSES)
                cur.execute(
                    """
                    INSERT INTO remediation_actions (action_id, finding_id, playbook, status, proposed_by)
                    VALUES (%s, %s, %s, 'PROPOSED', %s)
                    ON CONFLICT (finding_id) WHERE status = ANY(%s) DO NOTHING
                    RETURNING *
                    """,
                    (str(uuid.uuid4()), finding_id, playbook, proposed_by, open_statuses),
                )
                created = cur.fetchone()
                if created is not None:
                    self._audit(
                        cur,
                        str(created["action_id"]),
                        "proposed",
                        proposed_by,
                        None,
                        PROPOSED,
                        {"finding_id": finding_id, "playbook": playbook},
                    )
                    conn.commit()
                    return dict(created), "created"

                cur.execute(
                    "SELECT * FROM remediation_actions WHERE finding_id = %s AND status = ANY(%s)",
                    (finding_id, open_statuses),
                )
                existing = cur.fetchone()
                if existing is None:
                    raise RuntimeError("remediation proposal conflict did not return an existing action")
            conn.commit()
            return dict(existing), "existing"
        except Exception:
            self._db.rollback(conn)
            raise

    def approve(self, action_id: str, approved_by: str) -> Dict[str, Any]:
        """Approve a proposal. ``PROPOSED -> APPROVED``, won by exactly one caller."""
        approved_by = _require_actor(approved_by, "Approver")
        return self._transition(
            action_id,
            event="approved",
            actor=approved_by,
            from_statuses=(PROPOSED,),
            to_status=APPROVED,
            assignments=", approved_by = %s, approved_at = CURRENT_TIMESTAMP",
            params=(approved_by,),
        )

    def reject(self, action_id: str, rejected_by: str, reason: str = "") -> Dict[str, Any]:
        """Close an action without executing it, or after a failed attempt."""
        rejected_by = _require_actor(rejected_by, "Rejecter")
        return self._transition(
            action_id,
            event="rejected",
            actor=rejected_by,
            from_statuses=_REJECTABLE,
            to_status=REJECTED,
            detail={"reason": reason},
        )

    def begin_execution(self, action_id: str, executor: str) -> Dict[str, Any]:
        """Grant permission to execute an approved, allowlisted action, once.

        The returned row is the execution grant. A second call for the same
        action, concurrent or retried, raises :class:`InvalidTransition` and
        never returns a grant.
        """
        executor = _require_actor(executor, "Executor")
        conn = self._db._get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT playbook, status FROM remediation_actions WHERE action_id = %s", (action_id,))
                row = cur.fetchone()
                if row is None:
                    raise RemediationNotFound(f"Remediation action {action_id} not found")
                if not self.is_allowlisted(row["playbook"]):
                    self._audit(
                        cur,
                        action_id,
                        "execution_refused",
                        executor,
                        row["status"],
                        row["status"],
                        {"reason": "playbook_not_allowlisted", "playbook": row["playbook"]},
                    )
                    conn.commit()
                    raise NotAllowlisted(f"Playbook {row['playbook']} is not eligible for automated execution")
            conn.rollback()
        except Exception:
            self._db.rollback(conn)
            raise

        return self._transition(
            action_id,
            event="execution_started",
            actor=executor,
            from_statuses=(APPROVED,),
            to_status=EXECUTING,
            assignments=", executed_by = %s, executed_at = CURRENT_TIMESTAMP",
            params=(executor,),
        )

    def complete_execution(
        self, action_id: str, executor: str, succeeded: bool, detail: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Record the outcome. Only the executor that holds the grant may do so.

        Success moves to ``PENDING_VERIFICATION``, never to ``VERIFIED``:
        a script exiting cleanly is not evidence the finding is gone.
        """
        executor = _require_actor(executor, "Executor")
        return self._transition(
            action_id,
            event="execution_succeeded" if succeeded else "execution_failed",
            actor=executor,
            from_statuses=(EXECUTING,),
            to_status=PENDING_VERIFICATION if succeeded else EXECUTION_FAILED,
            extra_where=" AND a.executed_by = %s",
            where_params=(executor,),
            detail=detail,
        )

    def verify(self, action_id: str, scan_id: str, actor: str = "system") -> Tuple[Dict[str, Any], str]:
        """Decide whether a remediation worked, using a later completed scan.

        Returns ``(action, outcome)``: ``verified``, ``failed`` or
        ``inconclusive``. Only ``verified`` closes the action. The rescan must
        be completed, cover the same subscription and have finished after the
        execution, and its rule evaluation for the exact resource must be
        ``PASS``. A missing, ``UNKNOWN`` or ``ERROR`` evaluation proves nothing
        and is recorded as inconclusive rather than treated as cleared.
        """
        actor = _require_actor(actor, "Verifier")
        conn = self._db._get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM remediation_actions WHERE action_id = %s FOR UPDATE", (action_id,))
                action = cur.fetchone()
                if action is None:
                    raise RemediationNotFound(f"Remediation action {action_id} not found")
                if action["status"] not in _VERIFIABLE:
                    raise InvalidTransition(action_id, "verified", action["status"])

                cur.execute(
                    """
                    SELECT f.rule_id, f.resource_id, s.subscription_id
                    FROM findings f JOIN scans s ON s.scan_id = f.scan_id
                    WHERE f.id = %s
                    """,
                    (action["finding_id"],),
                )
                finding = cur.fetchone()
                if finding is None:
                    raise RemediationNotFound(f"Finding {action['finding_id']} not found")

                cur.execute(
                    "SELECT status, subscription_id, completed_at, completed_at > %s AS after_execution "
                    "FROM scans WHERE scan_id = %s",
                    (action["executed_at"], scan_id),
                )
                scan = cur.fetchone()
                if scan is None:
                    raise RemediationNotFound(f"Scan {scan_id} not found")
                if (
                    scan["status"] != "completed"
                    or scan["subscription_id"] != finding["subscription_id"]
                    or not scan["after_execution"]
                ):
                    raise RemediationError(
                        f"Scan {scan_id} is not a completed rescan of this subscription after the execution"
                    )

                resource_id = finding["resource_id"] or subscription_scope_id(finding["subscription_id"])
                cur.execute(
                    "SELECT status FROM rule_evaluations WHERE scan_id = %s AND rule_id = %s AND resource_id = %s",
                    (scan_id, finding["rule_id"], resource_id),
                )
                evaluation = cur.fetchone()
                observed = evaluation["status"] if evaluation else None
                detail = {"scan_id": scan_id, "rule_id": finding["rule_id"], "observed": observed}

                if observed == EvaluationStatus.PASS:
                    outcome, to_status, event = "verified", VERIFIED, "verification_passed"
                elif observed == EvaluationStatus.FAIL:
                    outcome, to_status, event = "failed", VERIFICATION_FAILED, "verification_failed"
                else:
                    self._audit(
                        cur, action_id, "verification_inconclusive", actor, action["status"], action["status"], detail
                    )
                    conn.commit()
                    return dict(action), "inconclusive"

                cur.execute(
                    """
                    UPDATE remediation_actions
                    SET status = %s, updated_at = CURRENT_TIMESTAMP, verification_scan_id = %s,
                        verified_at = CASE WHEN %s = 'VERIFIED' THEN CURRENT_TIMESTAMP ELSE verified_at END
                    WHERE action_id = %s
                    RETURNING *
                    """,
                    (to_status, scan_id, to_status, action_id),
                )
                updated = dict(cur.fetchone())
                self._audit(cur, action_id, event, actor, action["status"], to_status, detail)
            conn.commit()
            return updated, outcome
        except Exception:
            self._db.rollback(conn)
            raise

    # ------------------------------------------------------------------ #
    # Reads                                                                 #
    # ------------------------------------------------------------------ #

    def get_action(self, action_id: str) -> Optional[Dict[str, Any]]:
        conn = self._db._get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM remediation_actions WHERE action_id = %s", (action_id,))
                row = cur.fetchone()
            conn.commit()
            return dict(row) if row else None
        except Exception:
            self._db.rollback(conn)
            raise

    def get_audit_trail(self, action_id: str) -> List[Dict[str, Any]]:
        """Return every recorded step for an action, oldest first."""
        conn = self._db._get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM remediation_audit_log WHERE action_id = %s ORDER BY audit_id",
                    (action_id,),
                )
                rows = [dict(r) for r in cur.fetchall()]
            conn.commit()
            return rows
        except Exception:
            self._db.rollback(conn)
            raise
