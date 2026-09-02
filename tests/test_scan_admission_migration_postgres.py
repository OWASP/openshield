"""Migration-time safety for the one-active-scan unique index.

``CREATE UNIQUE INDEX CONCURRENTLY`` fails -- and leaves an INVALID index
behind -- when a deployment already holds several active scans for one
subscription.  These tests run the real migration against a throwaway
PostgreSQL database seeded with exactly that legacy shape.
"""

import os
import uuid
from contextlib import contextmanager

import psycopg2
import pytest
from alembic import command
from alembic.config import Config


pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="DATABASE_URL is required for PostgreSQL tests"
)

# The revision immediately before scan admission is introduced.
_BEFORE_ADMISSION = "f2b6d8e1a4c9"
_ADMISSION = "a7c5e9d2f1b4"
_ACTIVE_INDEX = "uq_scans_one_active_per_subscription"
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@contextmanager
def _scratch_database():
    """Create and drop a database dedicated to one migration test."""
    base = os.environ["DATABASE_URL"].rsplit("/", 1)[0]
    name = f"openshield_mig_{uuid.uuid4().hex[:12]}"
    admin = psycopg2.connect(f"{base}/postgres")
    admin.autocommit = True
    try:
        with admin.cursor() as cur:
            cur.execute(f'CREATE DATABASE "{name}"')
        yield f"{base}/{name}"
    finally:
        with admin.cursor() as cur:
            cur.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s AND pid <> pg_backend_pid()",
                (name,),
            )
            cur.execute(f'DROP DATABASE IF EXISTS "{name}"')
        admin.close()


def _alembic_config() -> Config:
    """Alembic config that does not touch this process's logging setup.

    Passing alembic.ini would make ``env.py`` call ``fileConfig()``, which
    disables every logger that already exists -- silencing the rest of the
    test session. Only ``script_location`` is actually needed here; ``env.py``
    reads the database URL from the environment.
    """
    config = Config()
    config.set_main_option("script_location", os.path.join(_REPO_ROOT, "alembic"))
    return config


def _upgrade(dsn: str, revision: str) -> None:
    """Run alembic against ``dsn`` without disturbing the ambient env."""
    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = dsn
    try:
        command.upgrade(_alembic_config(), revision)
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous


def _seed_active_scans(dsn: str, subscription_id: str, count: int) -> list[str]:
    scan_ids = [str(uuid.uuid4()) for _ in range(count)]
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            for offset, scan_id in enumerate(scan_ids):
                cur.execute(
                    """
                    INSERT INTO scans (scan_id, subscription_id, started_at, status)
                    VALUES (%s, %s, CURRENT_TIMESTAMP - (%s * INTERVAL '1 minute'), 'pending')
                    """,
                    (scan_id, subscription_id, offset),
                )
    return scan_ids


def _index_is_valid(dsn: str, name: str):
    """Return True/False for a present index, or None when it does not exist."""
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT i.indisvalid
                FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
                WHERE c.relname = %s
                """,
                (name,),
            )
            row = cur.fetchone()
    return None if row is None else row[0]


def test_legacy_duplicate_active_scans_fail_the_migration_with_an_actionable_error():
    subscription_id = str(uuid.uuid4())
    with _scratch_database() as dsn:
        _upgrade(dsn, _BEFORE_ADMISSION)
        _seed_active_scans(dsn, subscription_id, 2)

        with pytest.raises(RuntimeError) as excinfo:
            _upgrade(dsn, _ADMISSION)

        message = str(excinfo.value)
        assert subscription_id in message
        assert "2 active" in message
        # The operator is told what to do, and no unusable index was left behind.
        assert "Resolve them first" in message
        assert _index_is_valid(dsn, _ACTIVE_INDEX) is None

        # Historical rows are untouched: the migration decides nothing for us.
        with psycopg2.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM scans WHERE subscription_id = %s", (subscription_id,))
                assert cur.fetchone()[0] == 2


def test_migration_succeeds_and_enforces_the_contract_after_cleanup():
    subscription_id = str(uuid.uuid4())
    with _scratch_database() as dsn:
        _upgrade(dsn, _BEFORE_ADMISSION)
        scan_ids = _seed_active_scans(dsn, subscription_id, 2)

        with pytest.raises(RuntimeError):
            _upgrade(dsn, _ADMISSION)

        # The documented cleanup: retire the superseded scan, keep the record.
        with psycopg2.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE scans SET status = 'failed' WHERE scan_id = %s", (scan_ids[1],))

        _upgrade(dsn, _ADMISSION)
        assert _index_is_valid(dsn, _ACTIVE_INDEX) is True

        conn = psycopg2.connect(dsn)
        try:
            with conn.cursor() as cur:
                # Both historical rows survived the migration.
                cur.execute("SELECT COUNT(*) FROM scans WHERE subscription_id = %s", (subscription_id,))
                assert cur.fetchone()[0] == 2

                # A second active scan for the same subscription is now refused.
                with pytest.raises(psycopg2.errors.UniqueViolation):
                    cur.execute(
                        """
                        INSERT INTO scans (scan_id, subscription_id, started_at, status)
                        VALUES (%s, %s, CURRENT_TIMESTAMP, 'running')
                        """,
                        (str(uuid.uuid4()), subscription_id),
                    )
            conn.rollback()

            with conn.cursor() as cur:
                # Terminal scans stay unconstrained: history keeps accumulating.
                for _ in range(3):
                    cur.execute(
                        """
                        INSERT INTO scans (scan_id, subscription_id, started_at, status)
                        VALUES (%s, %s, CURRENT_TIMESTAMP, 'completed')
                        """,
                        (str(uuid.uuid4()), subscription_id),
                    )
                # Idempotency-key uniqueness is per subscription and ignores NULLs.
                for _ in range(2):
                    cur.execute(
                        """
                        INSERT INTO scans (scan_id, subscription_id, started_at, status, idempotency_key)
                        VALUES (%s, %s, CURRENT_TIMESTAMP, 'completed', NULL)
                        """,
                        (str(uuid.uuid4()), subscription_id),
                    )
                cur.execute(
                    """
                    INSERT INTO scans (scan_id, subscription_id, started_at, status, idempotency_key)
                    VALUES (%s, %s, CURRENT_TIMESTAMP, 'completed', 'key-1')
                    """,
                    (str(uuid.uuid4()), subscription_id),
                )
            conn.commit()

            with conn.cursor() as cur:
                with pytest.raises(psycopg2.errors.UniqueViolation):
                    cur.execute(
                        """
                        INSERT INTO scans (scan_id, subscription_id, started_at, status, idempotency_key)
                        VALUES (%s, %s, CURRENT_TIMESTAMP, 'completed', 'key-1')
                        """,
                        (str(uuid.uuid4()), subscription_id),
                    )
            conn.rollback()

            # The same key under a different subscription is still admissible.
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO scans (scan_id, subscription_id, started_at, status, idempotency_key)
                    VALUES (%s, %s, CURRENT_TIMESTAMP, 'completed', 'key-1')
                    """,
                    (str(uuid.uuid4()), str(uuid.uuid4())),
                )
            conn.commit()
        finally:
            conn.close()


def test_an_invalid_index_left_by_a_failed_build_is_replaced_not_inherited():
    """A retry after a failed CONCURRENTLY build must not trip over its debris."""
    subscription_id = str(uuid.uuid4())
    with _scratch_database() as dsn:
        _upgrade(dsn, _BEFORE_ADMISSION)
        _seed_active_scans(dsn, subscription_id, 1)

        # Reproduce the debris a failed concurrent build leaves behind.
        conn = psycopg2.connect(dsn)
        conn.autocommit = True
        try:
            with conn.cursor() as cur:
                cur.execute(
                    f"CREATE UNIQUE INDEX CONCURRENTLY {_ACTIVE_INDEX} "
                    "ON scans (subscription_id) WHERE status IN ('pending', 'running')"
                )
                cur.execute(
                    "UPDATE pg_index SET indisvalid = false WHERE indexrelid = %s::regclass",
                    (_ACTIVE_INDEX,),
                )
        finally:
            conn.close()
        assert _index_is_valid(dsn, _ACTIVE_INDEX) is False

        _upgrade(dsn, _ADMISSION)
        assert _index_is_valid(dsn, _ACTIVE_INDEX) is True
