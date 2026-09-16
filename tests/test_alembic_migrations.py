"""Alembic migration-chain and populated-database checks for rule_evaluations (#263).

The head/chain checks are static (parse revision/down_revision out of every
migration file) and always run. The CHECK-constraint checks are populated-
database checks: CI applies `alembic upgrade head` against a real Postgres
before pytest runs (see .github/workflows/ci.yml), so DATABASE_URL points at
an already-migrated database there. They're skipped when no DATABASE_URL is
set (e.g. a local run with no Postgres available).
"""

import os
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
VERSIONS_DIR = ROOT / "alembic" / "versions"

_REV_RE = re.compile(r"^revision:.*=\s*[\"']([a-f0-9]+)[\"']", re.MULTILINE)
_DOWN_RE = re.compile(r"^down_revision.*=\s*[\"']([a-f0-9]+)[\"']", re.MULTILINE)


def _revision_graph():
    graph = {}
    for path in VERSIONS_DIR.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        rev = _REV_RE.search(text)
        down = _DOWN_RE.search(text)
        assert rev, f"{path.name}: no revision id found"
        graph[rev.group(1)] = (path.name, down.group(1) if down else None)
    return graph


def test_single_alembic_head():
    """Exactly one migration must have no other migration pointing at it as
    its parent — two heads means a broken/forked migration history."""
    graph = _revision_graph()
    downs = {down for _, down in graph.values() if down}
    heads = [rev for rev in graph if rev not in downs]
    assert len(heads) == 1, f"expected exactly one Alembic head, found {heads}"


def test_rule_evaluations_migration_chains_after_severity_contract_v1():
    graph = _revision_graph()
    _, down = graph["3f59f83a5253"]
    assert down == "d8e4f6a1b2c3"


def test_rule_evaluations_migration_defines_all_five_statuses():
    migration = (VERSIONS_DIR / "3f59f83a5253_rule_evaluations.py").read_text(encoding="utf-8")
    for status in ("PASS", "FAIL", "UNKNOWN", "ERROR", "NOT_APPLICABLE"):
        assert f"'{status}'" in migration


# ── Populated-database checks (require a live migrated Postgres) ───────────

DATABASE_URL = os.environ.get("DATABASE_URL")
pytestmark_db = pytest.mark.skipif(not DATABASE_URL, reason="requires a live migrated database (DATABASE_URL)")


def _conn():
    import psycopg2

    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn


def _seed_scan(cur, scan_id):
    cur.execute(
        "INSERT INTO scans (scan_id, subscription_id, started_at, status) "
        "VALUES (%s, %s, now(), 'completed') ON CONFLICT (scan_id) DO NOTHING",
        (scan_id, "00000000-0000-0000-0000-000000000001"),
    )


@pytestmark_db
def test_rule_evaluations_check_constraint_rejects_unsupported_status():
    import psycopg2

    conn = _conn()
    try:
        with conn.cursor() as cur:
            _seed_scan(cur, "10000000-0000-0000-0000-000000000001")
            with pytest.raises(psycopg2.errors.CheckViolation):
                cur.execute(
                    "INSERT INTO rule_evaluations "
                    "(scan_id, rule_id, resource_id, resource_type, status, evaluated_at) "
                    "VALUES (%s, 'AZ-TEST-001', '/subscriptions/x', '', 'BOGUS', now())",
                    ("10000000-0000-0000-0000-000000000001",),
                )
    finally:
        conn.rollback()
        conn.close()


@pytestmark_db
def test_rule_evaluations_check_constraint_rejects_empty_resource_id():
    import psycopg2

    conn = _conn()
    try:
        with conn.cursor() as cur:
            _seed_scan(cur, "10000000-0000-0000-0000-000000000002")
            with pytest.raises(psycopg2.errors.CheckViolation):
                cur.execute(
                    "INSERT INTO rule_evaluations "
                    "(scan_id, rule_id, resource_id, resource_type, status, evaluated_at) "
                    "VALUES (%s, 'AZ-TEST-001', '', '', 'PASS', now())",
                    ("10000000-0000-0000-0000-000000000002",),
                )
    finally:
        conn.rollback()
        conn.close()


@pytestmark_db
def test_rule_evaluations_check_constraint_requires_reason_code_for_unknown():
    import psycopg2

    conn = _conn()
    try:
        with conn.cursor() as cur:
            _seed_scan(cur, "10000000-0000-0000-0000-000000000003")
            with pytest.raises(psycopg2.errors.CheckViolation):
                cur.execute(
                    "INSERT INTO rule_evaluations "
                    "(scan_id, rule_id, resource_id, resource_type, status, reason_code, evaluated_at) "
                    "VALUES (%s, 'AZ-TEST-001', '/subscriptions/x', '', 'UNKNOWN', NULL, now())",
                    ("10000000-0000-0000-0000-000000000003",),
                )
    finally:
        conn.rollback()
        conn.close()


@pytestmark_db
def test_rule_evaluations_accepts_a_valid_pass_row_and_finding_id_is_nullable():
    conn = _conn()
    try:
        with conn.cursor() as cur:
            _seed_scan(cur, "10000000-0000-0000-0000-000000000004")
            cur.execute(
                "INSERT INTO rule_evaluations "
                "(scan_id, rule_id, resource_id, resource_type, status, evaluated_at) "
                "VALUES (%s, 'AZ-TEST-001', '/subscriptions/x', 'Microsoft.Test/resources', 'PASS', now()) "
                "RETURNING finding_id",
                ("10000000-0000-0000-0000-000000000004",),
            )
            assert cur.fetchone()[0] is None
    finally:
        conn.rollback()
        conn.close()
