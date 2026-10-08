"""PostgreSQL-backed tests for the remediation approval/idempotency/audit/rescan gate (#266)."""

import hashlib
import os
import threading
import uuid
from datetime import datetime, timedelta, timezone

import psycopg2
import pytest

from api.models.finding import DatabaseManager
from api.models.remediation import (
    APPROVED,
    EXECUTION_ALLOWLIST,
    EXECUTION_FAILED,
    EXECUTING,
    OPEN_STATUSES,
    PENDING_VERIFICATION,
    PROPOSED,
    REJECTED,
    VERIFICATION_FAILED,
    VERIFIED,
    InvalidTransition,
    NotAllowlisted,
    PlaybookChanged,
    PlaybookUnavailable,
    RemediationError,
    RemediationGate,
    RemediationNotFound,
)


pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="DATABASE_URL is required for PostgreSQL tests"
)

PLAYBOOK = "playbooks/cli/fix_az_test_001.sh"
SCRIPT_BODY = b"#!/usr/bin/env bash\nset -euo pipefail\naz storage account update --help\n"
RULE_ID = "AZ-TEST-001"


@pytest.fixture()
def dsn() -> str:
    return os.environ["DATABASE_URL"]


@pytest.fixture()
def playbook_root(tmp_path):
    """A throwaway repo root holding the one playbook the tests propose."""
    script = tmp_path / PLAYBOOK
    script.parent.mkdir(parents=True)
    script.write_bytes(SCRIPT_BODY)
    return tmp_path


@pytest.fixture()
def world(dsn):
    """Create scans/findings for one test and remove every trace afterwards."""
    created = {"scans": [], "findings": []}
    subscription_id = str(uuid.uuid4())

    def scan(completed_at=None, status="completed", subscription=None) -> str:
        scan_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO scans (scan_id, subscription_id, started_at, completed_at, status) "
                "VALUES (%s, %s, %s, %s, %s)",
                (scan_id, subscription or subscription_id, now, completed_at or now, status),
            )
        created["scans"].append(scan_id)
        return scan_id

    def finding(scan_id: str, playbook=PLAYBOOK, resource_id="/subscriptions/x/resource/1") -> int:
        with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO findings (scan_id, rule_id, rule_name, severity, resource_id, playbook, "
                "detected_at, finding_key) VALUES (%s, %s, 'Test rule', 'HIGH', %s, %s, CURRENT_TIMESTAMP, %s) "
                "RETURNING id",
                (scan_id, RULE_ID, resource_id, playbook, uuid.uuid4().hex),
            )
            finding_id = cur.fetchone()[0]
        created["findings"].append(finding_id)
        return finding_id

    def evaluation(scan_id: str, status: str, resource_id="/subscriptions/x/resource/1") -> None:
        reason_code = None if status in ("PASS", "FAIL") else "TEST_REASON"
        with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO rule_evaluations (scan_id, rule_id, resource_id, status, reason_code, evaluated_at) "
                "VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)",
                (scan_id, RULE_ID, resource_id, status, reason_code),
            )

    class World:
        pass

    w = World()
    w.subscription_id = subscription_id
    w.scan, w.finding, w.evaluation = scan, finding, evaluation
    yield w

    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        # The audit log rejects UPDATE, DELETE and TRUNCATE on purpose. Only this
        # teardown switches its triggers off, inside one transaction, to tidy up.
        cur.execute("ALTER TABLE remediation_audit_log DISABLE TRIGGER USER")
        cur.execute("DELETE FROM remediation_audit_log")
        cur.execute("ALTER TABLE remediation_audit_log ENABLE TRIGGER USER")
        cur.execute("DELETE FROM remediation_actions")
        cur.execute("DELETE FROM rule_evaluations WHERE scan_id = ANY(%s::uuid[])", (created["scans"],))
        cur.execute("DELETE FROM findings WHERE id = ANY(%s)", (created["findings"],))
        cur.execute("DELETE FROM scans WHERE scan_id = ANY(%s::uuid[])", (created["scans"],))


@pytest.fixture()
def gate(dsn, playbook_root):
    db = DatabaseManager(dsn)
    yield RemediationGate(db, allowlist={PLAYBOOK}, playbook_root=playbook_root)
    db.close()


def _run_concurrently(dsn: str, n: int, fn, playbook_root):
    """Run fn(gate, index) on n threads, each with its own connection, released together."""
    barrier = threading.Barrier(n)
    results: list = [None] * n

    def worker(i: int) -> None:
        db = DatabaseManager(dsn)
        try:
            barrier.wait(timeout=10)
            results[i] = ("ok", fn(RemediationGate(db, allowlist={PLAYBOOK}, playbook_root=playbook_root), i))
        except Exception as exc:  # noqa: BLE001 - the exception type is the result under test
            results[i] = ("err", exc)
        finally:
            db.close()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    return results


def _approved_action(gate, world):
    finding_id = world.finding(world.scan())
    action, _ = gate.propose(finding_id, "agent")
    return gate.approve(str(action["action_id"]), "alice")


def _executed_action(gate, world):
    action = _approved_action(gate, world)
    action_id = str(action["action_id"])
    gate.begin_execution(action_id, "runner-1")
    return gate.complete_execution(action_id, "runner-1", succeeded=True)


# --------------------------------------------------------------------------- #
# Proposal                                                                     #
# --------------------------------------------------------------------------- #


def test_allowlist_ships_empty():
    assert EXECUTION_ALLOWLIST == frozenset()


def test_propose_records_action_and_audit(gate, world):
    finding_id = world.finding(world.scan())

    action, outcome = gate.propose(finding_id, "agent")

    assert outcome == "created"
    assert action["status"] == PROPOSED
    assert action["playbook"] == PLAYBOOK
    trail = gate.get_audit_trail(str(action["action_id"]))
    assert [(e["event"], e["from_status"], e["to_status"], e["actor"]) for e in trail] == [
        ("proposed", None, PROPOSED, "agent")
    ]


def test_repeated_propose_returns_the_same_action(gate, world):
    finding_id = world.finding(world.scan())

    first, first_outcome = gate.propose(finding_id, "agent")
    second, second_outcome = gate.propose(finding_id, "agent")

    assert (first_outcome, second_outcome) == ("created", "existing")
    assert first["action_id"] == second["action_id"]
    assert len(gate.get_audit_trail(str(first["action_id"]))) == 1


def test_concurrent_proposals_create_exactly_one_action(dsn, gate, world, playbook_root):
    finding_id = world.finding(world.scan())

    results = _run_concurrently(dsn, 8, lambda g, i: g.propose(finding_id, f"agent-{i}"), playbook_root)

    assert all(kind == "ok" for kind, _ in results), results
    assert sorted(outcome for _, (_, outcome) in results) == ["created"] + ["existing"] * 7
    assert len({str(action["action_id"]) for _, (action, _) in results}) == 1


def test_propose_rejects_unknown_finding_missing_playbook_and_blank_actor(gate, world):
    with pytest.raises(RemediationNotFound):
        gate.propose(2_000_000_000, "agent")
    with pytest.raises(RemediationError, match="no playbook"):
        gate.propose(world.finding(world.scan(), playbook=""), "agent")
    with pytest.raises(ValueError):
        gate.propose(world.finding(world.scan()), "  ")


def test_finding_is_released_only_by_verified_or_rejected(gate, world):
    finding_id = world.finding(world.scan())
    action, _ = gate.propose(finding_id, "agent")
    gate.reject(str(action["action_id"]), "alice", "not wanted")

    replacement, outcome = gate.propose(finding_id, "agent")

    assert outcome == "created"
    assert replacement["action_id"] != action["action_id"]
    assert REJECTED not in OPEN_STATUSES and VERIFIED not in OPEN_STATUSES


# --------------------------------------------------------------------------- #
# Approval                                                                     #
# --------------------------------------------------------------------------- #


def test_execution_is_refused_without_approval(gate, world):
    action, _ = gate.propose(world.finding(world.scan()), "agent")

    with pytest.raises(InvalidTransition) as excinfo:
        gate.begin_execution(str(action["action_id"]), "runner-1")

    assert excinfo.value.current == PROPOSED
    assert gate.get_action(str(action["action_id"]))["status"] == PROPOSED


def test_concurrent_approvals_have_exactly_one_winner(dsn, gate, world, playbook_root):
    action, _ = gate.propose(world.finding(world.scan()), "agent")
    action_id = str(action["action_id"])

    results = _run_concurrently(dsn, 8, lambda g, i: g.approve(action_id, f"approver-{i}"), playbook_root)

    winners = [r for kind, r in results if kind == "ok"]
    losers = [r for kind, r in results if kind == "err"]
    assert len(winners) == 1
    assert len(losers) == 7 and all(isinstance(e, InvalidTransition) for e in losers)
    stored = gate.get_action(action_id)
    assert stored["status"] == APPROVED
    assert stored["approved_by"] == winners[0]["approved_by"]
    assert [e["event"] for e in gate.get_audit_trail(action_id)].count("approved") == 1


def test_approve_requires_an_identified_approver(gate, world):
    action, _ = gate.propose(world.finding(world.scan()), "agent")
    with pytest.raises(ValueError):
        gate.approve(str(action["action_id"]), "")


def test_reject_records_the_real_predecessor_status(gate, world):
    action = _approved_action(gate, world)

    gate.reject(str(action["action_id"]), "alice", "changed my mind")

    last = gate.get_audit_trail(str(action["action_id"]))[-1]
    assert (last["event"], last["from_status"], last["to_status"]) == ("rejected", APPROVED, REJECTED)
    assert last["detail"] == {"reason": "changed my mind"}


# --------------------------------------------------------------------------- #
# Execution                                                                    #
# --------------------------------------------------------------------------- #


def test_default_gate_refuses_every_playbook_and_audits_the_refusal(dsn, world, playbook_root):
    db = DatabaseManager(dsn)
    try:
        strict = RemediationGate(db, playbook_root=playbook_root)
        action, _ = strict.propose(world.finding(world.scan()), "agent")
        strict.approve(str(action["action_id"]), "alice")

        with pytest.raises(NotAllowlisted):
            strict.begin_execution(str(action["action_id"]), "runner-1")

        assert strict.get_action(str(action["action_id"]))["status"] == APPROVED
        events = [e["event"] for e in strict.get_audit_trail(str(action["action_id"]))]
        assert events[-1] == "execution_refused"
    finally:
        db.close()


def test_a_retried_execution_never_gets_a_second_grant(gate, world):
    action = _approved_action(gate, world)
    action_id = str(action["action_id"])

    grant = gate.begin_execution(action_id, "runner-1")
    with pytest.raises(InvalidTransition) as excinfo:
        gate.begin_execution(action_id, "runner-1")

    assert grant["status"] == EXECUTING
    assert excinfo.value.current == EXECUTING
    assert [e["event"] for e in gate.get_audit_trail(action_id)].count("execution_started") == 1


def test_concurrent_execution_requests_yield_exactly_one_grant(dsn, gate, world, playbook_root):
    action = _approved_action(gate, world)
    action_id = str(action["action_id"])

    results = _run_concurrently(dsn, 8, lambda g, i: g.begin_execution(action_id, f"runner-{i}"), playbook_root)

    grants = [r for kind, r in results if kind == "ok"]
    refusals = [r for kind, r in results if kind == "err"]
    assert len(grants) == 1
    assert len(refusals) == 7 and all(isinstance(e, InvalidTransition) for e in refusals)
    assert gate.get_action(action_id)["executed_by"] == grants[0]["executed_by"]
    assert [e["event"] for e in gate.get_audit_trail(action_id)].count("execution_started") == 1


def test_a_crashed_execution_is_left_executing_and_cannot_be_retried(gate, world):
    action = _approved_action(gate, world)
    action_id = str(action["action_id"])
    gate.begin_execution(action_id, "runner-1")

    # runner-1 dies here: no complete_execution call.
    with pytest.raises(InvalidTransition):
        gate.begin_execution(action_id, "runner-2")

    assert gate.get_action(action_id)["status"] == EXECUTING


def test_only_the_grant_holder_can_report_the_outcome(gate, world):
    action = _approved_action(gate, world)
    action_id = str(action["action_id"])
    gate.begin_execution(action_id, "runner-1")

    with pytest.raises(InvalidTransition):
        gate.complete_execution(action_id, "runner-2", succeeded=True)

    assert gate.get_action(action_id)["status"] == EXECUTING


def test_successful_execution_awaits_verification_and_failure_stays_open(gate, world):
    done = _executed_action(gate, world)
    assert done["status"] == PENDING_VERIFICATION

    action = _approved_action(gate, world)
    action_id = str(action["action_id"])
    gate.begin_execution(action_id, "runner-1")
    failed = gate.complete_execution(action_id, "runner-1", succeeded=False, detail={"exit_code": 2})
    assert failed["status"] == EXECUTION_FAILED
    assert EXECUTION_FAILED in OPEN_STATUSES
    with pytest.raises(InvalidTransition):
        gate.begin_execution(action_id, "runner-1")


# --------------------------------------------------------------------------- #
# Rescan verification                                                          #
# --------------------------------------------------------------------------- #


def _rescan(world, offset=timedelta(seconds=5), **kwargs) -> str:
    return world.scan(completed_at=datetime.now(timezone.utc) + offset, **kwargs)


def test_pass_on_the_rescan_verifies_and_releases_the_finding(gate, world):
    action = _executed_action(gate, world)
    action_id = str(action["action_id"])
    rescan = _rescan(world)
    world.evaluation(rescan, "PASS")

    updated, outcome = gate.verify(action_id, rescan)

    assert outcome == "verified"
    assert updated["status"] == VERIFIED and updated["verification_scan_id"] is not None
    assert updated["verified_at"] is not None
    last = gate.get_audit_trail(action_id)[-1]
    assert (last["event"], last["detail"]["observed"]) == ("verification_passed", "PASS")


def test_a_still_failing_rescan_stays_open_as_verification_failed(gate, world):
    action = _executed_action(gate, world)
    action_id = str(action["action_id"])
    rescan = _rescan(world)
    world.evaluation(rescan, "FAIL")

    updated, outcome = gate.verify(action_id, rescan)

    assert outcome == "failed"
    assert updated["status"] == VERIFICATION_FAILED
    assert updated["verified_at"] is None
    with pytest.raises(InvalidTransition):
        gate.begin_execution(action_id, "runner-1")
    replacement, proposal_outcome = gate.propose(updated["finding_id"], "agent")
    assert proposal_outcome == "existing" and replacement["action_id"] == updated["action_id"]


@pytest.mark.parametrize("observed", [None, "UNKNOWN", "ERROR", "NOT_APPLICABLE"])
def test_missing_or_non_conclusive_evidence_never_closes_the_action(gate, world, observed):
    action = _executed_action(gate, world)
    action_id = str(action["action_id"])
    rescan = _rescan(world)
    if observed:
        world.evaluation(rescan, observed)

    updated, outcome = gate.verify(action_id, rescan)

    assert outcome == "inconclusive"
    assert updated["status"] == PENDING_VERIFICATION
    assert gate.get_audit_trail(action_id)[-1]["event"] == "verification_inconclusive"


def test_a_failed_verification_can_later_be_verified_by_a_fresh_rescan(gate, world):
    action = _executed_action(gate, world)
    action_id = str(action["action_id"])
    first = _rescan(world)
    world.evaluation(first, "FAIL")
    gate.verify(action_id, first)
    second = _rescan(world, timedelta(seconds=10))
    world.evaluation(second, "PASS")

    _, outcome = gate.verify(action_id, second)

    assert outcome == "verified"
    assert gate.get_action(action_id)["status"] == VERIFIED


def test_rescan_must_be_completed_later_and_for_the_same_subscription(gate, world):
    action = _executed_action(gate, world)
    action_id = str(action["action_id"])
    candidates = {
        "older than the execution": world.scan(completed_at=datetime.now(timezone.utc) - timedelta(days=1)),
        "not completed": _rescan(world, status="running"),
        "another subscription": _rescan(world, subscription=str(uuid.uuid4())),
    }
    for scan_id in candidates.values():
        world.evaluation(scan_id, "PASS")

    for label, scan_id in candidates.items():
        with pytest.raises(RemediationError, match="completed rescan"):
            gate.verify(action_id, scan_id)
        assert gate.get_action(action_id)["status"] == PENDING_VERIFICATION, label


def test_verification_requires_a_pending_action(gate, world):
    action = _approved_action(gate, world)
    rescan = _rescan(world)
    world.evaluation(rescan, "PASS")

    with pytest.raises(InvalidTransition) as excinfo:
        gate.verify(str(action["action_id"]), rescan)

    assert excinfo.value.current == APPROVED


def test_concurrent_verification_of_one_action_settles_once(dsn, gate, world, playbook_root):
    action = _executed_action(gate, world)
    action_id = str(action["action_id"])
    rescan = _rescan(world)
    world.evaluation(rescan, "PASS")

    results = _run_concurrently(dsn, 6, lambda g, i: g.verify(action_id, rescan), playbook_root)

    outcomes = [r[1] for kind, r in results if kind == "ok"]
    assert outcomes.count("verified") == 1
    assert all(isinstance(r, InvalidTransition) for kind, r in results if kind == "err")
    assert [e["event"] for e in gate.get_audit_trail(action_id)].count("verification_passed") == 1


# --------------------------------------------------------------------------- #
# Audit trail                                                                  #
# --------------------------------------------------------------------------- #


def test_full_lifecycle_is_audited_in_order(gate, world):
    action = _executed_action(gate, world)
    action_id = str(action["action_id"])
    rescan = _rescan(world)
    world.evaluation(rescan, "PASS")
    gate.verify(action_id, rescan)

    trail = gate.get_audit_trail(action_id)

    assert [e["event"] for e in trail] == [
        "proposed",
        "approved",
        "execution_started",
        "execution_succeeded",
        "verification_passed",
    ]
    assert [e["actor"] for e in trail] == ["agent", "alice", "runner-1", "runner-1", "system"]
    assert [e["to_status"] for e in trail] == [PROPOSED, APPROVED, EXECUTING, PENDING_VERIFICATION, VERIFIED]


def test_audit_log_is_append_only(dsn, gate, world):
    action, _ = gate.propose(world.finding(world.scan()), "agent")

    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        with pytest.raises(psycopg2.Error, match="append-only"):
            cur.execute(
                "UPDATE remediation_audit_log SET actor = 'mallory' WHERE action_id = %s", (str(action["action_id"]),)
            )
    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        with pytest.raises(psycopg2.Error, match="append-only"):
            cur.execute("DELETE FROM remediation_audit_log WHERE action_id = %s", (str(action["action_id"]),))

    assert gate.get_audit_trail(str(action["action_id"]))[0]["actor"] == "agent"


def test_unknown_action_is_reported_as_not_found(gate):
    missing = str(uuid.uuid4())
    with pytest.raises(RemediationNotFound):
        gate.approve(missing, "alice")
    assert gate.get_action(missing) is None


# --------------------------------------------------------------------------- #
# Audit trail cannot be wiped                                                  #
# --------------------------------------------------------------------------- #


def test_audit_log_cannot_be_truncated(dsn, gate, world):
    action, _ = gate.propose(world.finding(world.scan()), "agent")
    action_id = str(action["action_id"])

    with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
        with pytest.raises(psycopg2.Error, match="append-only"):
            cur.execute("TRUNCATE remediation_audit_log")

    assert [e["event"] for e in gate.get_audit_trail(action_id)] == ["proposed"]


# --------------------------------------------------------------------------- #
# Approval covers exactly what will run                                        #
# --------------------------------------------------------------------------- #


def test_proposal_pins_the_script_hash_and_the_target(gate, world):
    resource = "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct"
    finding_id = world.finding(world.scan(), resource_id=resource)

    action, _ = gate.propose(finding_id, "agent")

    assert action["playbook_sha256"] == hashlib.sha256(SCRIPT_BODY).hexdigest()
    assert action["resource_id"] == resource
    assert action["subscription_id"] == world.subscription_id


def test_approval_audit_row_records_what_the_approver_approved(gate, world):
    action = _approved_action(gate, world)

    approved = [e for e in gate.get_audit_trail(str(action["action_id"])) if e["event"] == "approved"]

    assert len(approved) == 1
    detail = approved[0]["detail"]
    assert detail["playbook"] == PLAYBOOK
    assert detail["playbook_sha256"] == hashlib.sha256(SCRIPT_BODY).hexdigest()
    assert detail["resource_id"] == action["resource_id"]
    assert detail["subscription_id"] == world.subscription_id


def test_a_script_edited_after_approval_is_never_granted(gate, world, playbook_root):
    action = _approved_action(gate, world)
    action_id = str(action["action_id"])
    (playbook_root / PLAYBOOK).write_bytes(SCRIPT_BODY + b"az group delete --name production --yes\n")

    with pytest.raises(PlaybookChanged):
        gate.begin_execution(action_id, "runner-1")

    assert gate.get_action(action_id)["status"] == APPROVED
    refusal = gate.get_audit_trail(action_id)[-1]
    assert refusal["event"] == "execution_refused"
    assert refusal["detail"]["reason"] == "playbook_changed"
    assert refusal["detail"]["approved_sha256"] == hashlib.sha256(SCRIPT_BODY).hexdigest()
    assert refusal["detail"]["current_sha256"] != refusal["detail"]["approved_sha256"]


def test_restoring_the_approved_script_makes_the_action_grantable_again(gate, world, playbook_root):
    action = _approved_action(gate, world)
    action_id = str(action["action_id"])
    script = playbook_root / PLAYBOOK
    script.write_bytes(SCRIPT_BODY + b"# tampered\n")
    with pytest.raises(PlaybookChanged):
        gate.begin_execution(action_id, "runner-1")

    script.write_bytes(SCRIPT_BODY)

    assert gate.begin_execution(action_id, "runner-1")["status"] == EXECUTING


def test_a_script_removed_after_approval_is_never_granted(gate, world, playbook_root):
    action = _approved_action(gate, world)
    action_id = str(action["action_id"])
    (playbook_root / PLAYBOOK).unlink()

    with pytest.raises(PlaybookChanged):
        gate.begin_execution(action_id, "runner-1")

    assert gate.get_action(action_id)["status"] == APPROVED
    assert gate.get_audit_trail(action_id)[-1]["detail"]["current_sha256"] is None


@pytest.mark.parametrize(
    "playbook",
    [
        "playbooks/cli/does_not_exist.sh",
        "../outside.sh",
        "playbooks/../../outside.sh",
        "/etc/passwd",
        "playbooks/cli",
    ],
)
def test_propose_refuses_a_playbook_that_is_missing_or_outside_playbooks(gate, world, playbook_root, playbook):
    (playbook_root.parent / "outside.sh").write_text("echo outside")
    finding_id = world.finding(world.scan(), playbook=playbook)

    with pytest.raises(PlaybookUnavailable):
        gate.propose(finding_id, "agent")

    with psycopg2.connect(os.environ["DATABASE_URL"]) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM remediation_actions WHERE finding_id = %s", (finding_id,))
        assert cur.fetchone()[0] == 0
