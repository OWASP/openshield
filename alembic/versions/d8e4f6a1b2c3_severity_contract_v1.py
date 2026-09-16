"""Enforce severity contract v1 and repair historical scan scores.

Revision ID: d8e4f6a1b2c3
Revises: c7a2e9f1b3d4
Create Date: 2026-08-21 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# Revision identifiers, used by Alembic.
revision: str = "d8e4f6a1b2c3"
down_revision: Union[str, Sequence[str], None] = "c7a2e9f1b3d4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_CONSTRAINT = "ck_findings_severity_v1"


def upgrade() -> None:
    """Normalize known aliases, reject unknown data, constrain and rescore."""
    op.execute(
        """
        DO $$
        DECLARE invalid_values text;
        BEGIN
            SELECT string_agg(value, ', ' ORDER BY value)
            INTO invalid_values
            FROM (
                SELECT DISTINCT UPPER(BTRIM(severity)) AS value
                FROM findings
                WHERE UPPER(BTRIM(severity)) NOT IN
                    ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'INFORMATIONAL')
            ) invalid;

            IF invalid_values IS NOT NULL THEN
                RAISE EXCEPTION 'Cannot apply severity contract v1; unsupported values: %', invalid_values;
            END IF;
        END $$;
        """
    )
    op.execute(
        """
        UPDATE findings
        SET severity = CASE UPPER(BTRIM(severity))
            WHEN 'INFORMATIONAL' THEN 'INFO'
            ELSE UPPER(BTRIM(severity))
        END
        WHERE severity <> CASE UPPER(BTRIM(severity))
            WHEN 'INFORMATIONAL' THEN 'INFO'
            ELSE UPPER(BTRIM(severity))
        END
        """
    )
    op.add_column(
        "scans",
        sa.Column(
            "severity_contract_version",
            sa.Text(),
            nullable=True,
        ),
    )
    op.execute(
        """
        ALTER TABLE findings
        ADD CONSTRAINT ck_findings_severity_v1
        CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'))
        NOT VALID
        """
    )
    op.execute("ALTER TABLE findings VALIDATE CONSTRAINT ck_findings_severity_v1")
    op.execute(
        """
        UPDATE scans AS scan
        SET score = GREATEST(
            0,
            100 - COALESCE((
                SELECT SUM(CASE finding.severity
                    WHEN 'CRITICAL' THEN 20
                    WHEN 'HIGH' THEN 10
                    WHEN 'MEDIUM' THEN 5
                    WHEN 'LOW' THEN 2
                    WHEN 'INFO' THEN 0
                END)
                FROM findings AS finding
                WHERE finding.scan_id = scan.scan_id
            ), 0)
        ),
        severity_contract_version = '1.0.0'
        WHERE scan.status = 'completed';
        """
    )


def downgrade() -> None:
    """Remove the v1 constraint; corrected historical scores remain corrected."""
    op.drop_constraint(_CONSTRAINT, "findings", type_="check")
    op.drop_column("scans", "severity_contract_version")
