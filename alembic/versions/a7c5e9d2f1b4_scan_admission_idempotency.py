"""Enforce durable scan admission and idempotency.

Revision ID: a7c5e9d2f1b4
Revises: f2b6d8e1a4c9
Create Date: 2026-08-29 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "a7c5e9d2f1b4"
down_revision: Union[str, Sequence[str], None] = "f2b6d8e1a4c9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_ACTIVE_INDEX = "uq_scans_one_active_per_subscription"
_KEY_INDEX = "uq_scans_subscription_idempotency_key"


def _assert_one_active_scan_per_subscription() -> None:
    """Fail with an actionable error instead of an unusable index.

    ``CREATE UNIQUE INDEX CONCURRENTLY`` on a table that already violates the
    constraint fails *and* leaves an INVALID index behind.  A deployment that
    predates the one-active-scan rule can legitimately hold several
    ``pending``/``running`` rows for one subscription, so this checks first and
    reports exactly which subscriptions block the upgrade.  Choosing which of
    those scans is authoritative is an operator decision -- deleting or
    completing production scan history automatically is never this migration's
    call.
    """
    rows = (
        op.get_bind()
        .execute(
            sa.text(
                """
                SELECT subscription_id, COUNT(*) AS active
                FROM scans
                WHERE status IN ('pending', 'running')
                GROUP BY subscription_id
                HAVING COUNT(*) > 1
                ORDER BY active DESC, subscription_id
                """
            )
        )
        .fetchall()
    )
    if not rows:
        return
    detail = ", ".join(f"{subscription_id} ({active} active)" for subscription_id, active in rows)
    raise RuntimeError(
        "Cannot enforce one active scan per subscription: "
        f"{len(rows)} subscription(s) already have more than one pending/running scan: {detail}. "
        "Resolve them first (let the scans finish, or mark the superseded rows "
        "'failed'), then re-run this migration. "
        "See docs/async-scan-architecture.md for the documented cleanup order."
    )


def upgrade() -> None:
    """Persist idempotency semantics and prevent more than one active scan."""
    op.add_column("scans", sa.Column("idempotency_key", sa.Text(), nullable=True))
    op.add_column("scans", sa.Column("request_fingerprint", sa.Text(), nullable=True))

    # Checked before either index is built so a blocked upgrade leaves the
    # schema exactly as it was, with the added columns unused and harmless.
    _assert_one_active_scan_per_subscription()

    with op.get_context().autocommit_block():
        # An earlier interrupted or failed CONCURRENTLY build leaves an INVALID
        # index that cannot serve queries but does occupy the name. Drop both
        # names first so retrying this migration is deterministic.
        op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {_KEY_INDEX}")
        op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {_ACTIVE_INDEX}")
        op.execute(
            f"""
            CREATE UNIQUE INDEX CONCURRENTLY {_KEY_INDEX}
            ON scans (subscription_id, idempotency_key)
            WHERE idempotency_key IS NOT NULL
            """
        )
        op.execute(
            f"""
            CREATE UNIQUE INDEX CONCURRENTLY {_ACTIVE_INDEX}
            ON scans (subscription_id)
            WHERE status IN ('pending', 'running')
            """
        )


def downgrade() -> None:
    """Remove scan admission metadata and constraints."""
    with op.get_context().autocommit_block():
        op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {_ACTIVE_INDEX}")
        op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {_KEY_INDEX}")
    op.drop_column("scans", "request_fingerprint")
    op.drop_column("scans", "idempotency_key")
