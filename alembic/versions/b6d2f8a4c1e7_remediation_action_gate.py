"""Add the approval, idempotency, audit and rescan gate for remediation actions.

Revision ID: b6d2f8a4c1e7
Revises: 3a76ff935bf6
Create Date: 2026-09-30 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "b6d2f8a4c1e7"
down_revision: Union[str, Sequence[str], None] = "3a76ff935bf6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_STATUS_CONSTRAINT = "ck_remediation_actions_status_v1"
_OPEN_INDEX = "uq_remediation_actions_one_open_per_finding"
_APPEND_ONLY_TRIGGER = "trg_remediation_audit_log_append_only"
_NO_TRUNCATE_TRIGGER = "trg_remediation_audit_log_no_truncate"
_APPEND_ONLY_FUNCTION = "remediation_audit_log_append_only"

_STATUSES = (
    "PROPOSED",
    "APPROVED",
    "EXECUTING",
    "EXECUTION_FAILED",
    "PENDING_VERIFICATION",
    "VERIFICATION_FAILED",
    "VERIFIED",
    "REJECTED",
)
# A finding may have at most one action that is still alive. EXECUTION_FAILED
# and VERIFICATION_FAILED are deliberately *not* terminal: they need a human
# decision, so a second proposal for the same finding cannot be created behind
# their back. Only VERIFIED and REJECTED release the finding.
_OPEN_STATUSES = (
    "PROPOSED",
    "APPROVED",
    "EXECUTING",
    "EXECUTION_FAILED",
    "PENDING_VERIFICATION",
    "VERIFICATION_FAILED",
)


def _in_list(values: Sequence[str]) -> str:
    return ", ".join(f"'{value}'" for value in values)


def upgrade() -> None:
    op.create_table(
        "remediation_actions",
        sa.Column("action_id", postgresql.UUID(), nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("playbook", sa.Text(), nullable=False),
        # What the approver is actually approving: the script's bytes at proposal
        # time and the exact target. begin_execution recomputes the hash and
        # refuses to run if the script changed after approval.
        sa.Column("playbook_sha256", sa.Text(), nullable=False),
        sa.Column("resource_id", sa.Text(), nullable=True),
        sa.Column("subscription_id", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'PROPOSED'")),
        sa.Column("proposed_by", sa.Text(), nullable=False),
        sa.Column("approved_by", sa.Text(), nullable=True),
        sa.Column("executed_by", sa.Text(), nullable=True),
        sa.Column("verification_scan_id", postgresql.UUID(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], name="remediation_actions_finding_id_fkey"),
        sa.ForeignKeyConstraint(
            ["verification_scan_id"], ["scans.scan_id"], name="remediation_actions_verification_scan_id_fkey"
        ),
        sa.PrimaryKeyConstraint("action_id", name="remediation_actions_pkey"),
    )
    op.create_check_constraint(
        _STATUS_CONSTRAINT,
        "remediation_actions",
        f"status IN ({_in_list(_STATUSES)})",
    )
    op.create_index("idx_remediation_actions_finding_id", "remediation_actions", ["finding_id"], unique=False)
    op.create_index("idx_remediation_actions_status", "remediation_actions", ["status"], unique=False)
    # The database, not the caller, guarantees one live action per finding, so
    # two concurrent proposals cannot both win.
    # The table was created empty two statements ago, so a plain (blocking)
    # index build costs nothing and keeps this revision transactional.
    op.execute(
        f"""
        CREATE UNIQUE INDEX {_OPEN_INDEX}
        ON remediation_actions (finding_id)
        WHERE status IN ({_in_list(_OPEN_STATUSES)})
        """
    )

    op.create_table(
        "remediation_audit_log",
        sa.Column("audit_id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("action_id", postgresql.UUID(), nullable=False),
        sa.Column("event", sa.Text(), nullable=False),
        sa.Column("from_status", sa.Text(), nullable=True),
        sa.Column("to_status", sa.Text(), nullable=True),
        sa.Column("actor", sa.Text(), nullable=False),
        sa.Column("detail", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column(
            "occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.ForeignKeyConstraint(
            ["action_id"], ["remediation_actions.action_id"], name="remediation_audit_log_action_id_fkey"
        ),
        sa.PrimaryKeyConstraint("audit_id", name="remediation_audit_log_pkey"),
    )
    op.create_index(
        "idx_remediation_audit_log_action_id", "remediation_audit_log", ["action_id", "audit_id"], unique=False
    )

    # The audit trail is only evidence if it cannot be rewritten afterwards.
    op.execute(
        f"""
        CREATE FUNCTION {_APPEND_ONLY_FUNCTION}() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'remediation_audit_log is append-only';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER {_APPEND_ONLY_TRIGGER}
        BEFORE UPDATE OR DELETE ON remediation_audit_log
        FOR EACH ROW EXECUTE FUNCTION {_APPEND_ONLY_FUNCTION}()
        """
    )
    # Row-level triggers never fire for TRUNCATE, which would otherwise empty the
    # trail in one statement, so it needs its own statement-level trigger.
    op.execute(
        f"""
        CREATE TRIGGER {_NO_TRUNCATE_TRIGGER}
        BEFORE TRUNCATE ON remediation_audit_log
        FOR EACH STATEMENT EXECUTE FUNCTION {_APPEND_ONLY_FUNCTION}()
        """
    )


def downgrade() -> None:
    op.execute(f"DROP TRIGGER IF EXISTS {_NO_TRUNCATE_TRIGGER} ON remediation_audit_log")
    op.execute(f"DROP TRIGGER IF EXISTS {_APPEND_ONLY_TRIGGER} ON remediation_audit_log")
    op.execute(f"DROP FUNCTION IF EXISTS {_APPEND_ONLY_FUNCTION}()")
    op.drop_index("idx_remediation_audit_log_action_id", table_name="remediation_audit_log")
    op.drop_table("remediation_audit_log")
    op.drop_index(_OPEN_INDEX, table_name="remediation_actions")
    op.drop_index("idx_remediation_actions_status", table_name="remediation_actions")
    op.drop_index("idx_remediation_actions_finding_id", table_name="remediation_actions")
    op.drop_constraint(_STATUS_CONSTRAINT, "remediation_actions", type_="check")
    op.drop_table("remediation_actions")
