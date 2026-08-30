"""Add finding lifecycle tables: scan_rule_outcomes, scan_lifecycle_applications,
finding_fingerprints, finding_lifecycles, finding_lifecycle_transitions, patterns.

Revision ID: e1f2a3b4c5d6
Revises: d8e4f6a1b2c3
Create Date: 2026-08-30 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# Revision identifiers, used by Alembic.
revision: str = "e1f2a3b4c5d6"
down_revision: Union[str, Sequence[str], None] = "d8e4f6a1b2c3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE scan_rule_outcomes (
            id BIGSERIAL PRIMARY KEY,
            scan_id UUID NOT NULL REFERENCES scans(scan_id),
            rule_id TEXT NOT NULL,
            rule_version TEXT NOT NULL DEFAULT '1',
            status TEXT NOT NULL,
            error_category TEXT,
            collector_version TEXT NOT NULL DEFAULT '1',
            inventory_boundary TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            subscription_id TEXT NOT NULL,
            started_at TIMESTAMPTZ,
            completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT ck_scan_rule_outcomes_status
                CHECK (status IN (
                    'SUCCESS','EMPTY_SUCCESS','PERMISSION_DENIED',
                    'TIMEOUT','FAILED','NOT_APPLICABLE'
                )),
            CONSTRAINT uq_scan_rule_outcomes_scan_rule
                UNIQUE (scan_id, rule_id)
        )
        """
    )

    op.execute(
        """
        CREATE TABLE scan_lifecycle_applications (
            scan_id UUID PRIMARY KEY REFERENCES scans(scan_id),
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            applied_by TEXT NOT NULL DEFAULT 'system'
        )
        """
    )

    op.execute(
        """
        CREATE TABLE finding_fingerprints (
            id BIGSERIAL PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            subscription_id TEXT NOT NULL,
            resource_id_normalized TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            evidence_key TEXT NOT NULL DEFAULT '',
            normalization_version TEXT NOT NULL DEFAULT '1',
            fingerprint_version TEXT NOT NULL DEFAULT '1',
            fingerprint_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_finding_fingerprints_hash UNIQUE (fingerprint_hash),
            CONSTRAINT uq_finding_fingerprints_identity
                UNIQUE (
                    tenant_id,
                    subscription_id,
                    resource_id_normalized,
                    rule_id,
                    evidence_key,
                    normalization_version
                )
        )
        """
    )

    op.execute(
        """
        CREATE TABLE finding_lifecycles (
            id BIGSERIAL PRIMARY KEY,
            fingerprint_id BIGINT NOT NULL REFERENCES finding_fingerprints(id),
            state TEXT NOT NULL,
            first_seen_scan_id UUID,
            last_seen_scan_id UUID,
            occurrence_count INTEGER NOT NULL DEFAULT 1,
            consecutive_success_count INTEGER NOT NULL DEFAULT 0,
            reopen_count INTEGER NOT NULL DEFAULT 0,
            row_version INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT ck_finding_lifecycles_state
                CHECK (state IN ('OPEN','RESOLVED','ACCEPTED','SUPPRESSED','REOPENED')),
            CONSTRAINT uq_finding_lifecycles_fingerprint
                UNIQUE (fingerprint_id)
        )
        """
    )

    op.execute(
        """
        CREATE TABLE finding_lifecycle_transitions (
            id BIGSERIAL PRIMARY KEY,
            lifecycle_id BIGINT NOT NULL REFERENCES finding_lifecycles(id),
            from_state TEXT,
            to_state TEXT NOT NULL,
            scan_id UUID,
            reason TEXT NOT NULL DEFAULT '',
            transitioned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )

    op.execute(
        """
        CREATE TABLE patterns (
            id BIGSERIAL PRIMARY KEY,
            pattern_type TEXT NOT NULL,
            lifecycle_id BIGINT REFERENCES finding_lifecycles(id),
            tenant_id TEXT NOT NULL,
            subscription_id TEXT NOT NULL,
            scan_id UUID,
            finding_ids JSONB NOT NULL DEFAULT '[]',
            threshold INTEGER NOT NULL,
            algorithm_version TEXT NOT NULL DEFAULT '1',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT ck_patterns_type
                CHECK (pattern_type IN (
                    'persistent_finding',
                    'cross_resource_recurrence',
                    'reopened_finding'
                )),
            CONSTRAINT uq_patterns_type_lifecycle_scan
                UNIQUE (pattern_type, lifecycle_id, scan_id)
        )
        """
    )


    # Indexes for hot query paths
    op.execute(
        "CREATE INDEX ix_finding_fingerprints_tenant_sub ON finding_fingerprints (tenant_id, subscription_id)"
    )
    op.execute(
        "CREATE INDEX ix_finding_lifecycles_state ON finding_lifecycles (state) WHERE state IN ('OPEN', 'REOPENED')"
    )
    op.execute(
        "CREATE INDEX ix_finding_lifecycle_transitions_lifecycle_id ON finding_lifecycle_transitions (lifecycle_id)"
    )
    op.execute(
        "CREATE INDEX ix_patterns_sub_created ON patterns (subscription_id, created_at DESC)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS patterns")
    op.execute("DROP TABLE IF EXISTS finding_lifecycle_transitions")
    op.execute("DROP TABLE IF EXISTS finding_lifecycles")
    op.execute("DROP TABLE IF EXISTS finding_fingerprints")
    op.execute("DROP TABLE IF EXISTS scan_lifecycle_applications")
    op.execute("DROP TABLE IF EXISTS scan_rule_outcomes")
