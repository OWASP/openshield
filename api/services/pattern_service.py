"""PatternService: detects and publishes security patterns from lifecycle state."""

import json
import logging
from typing import Any

import psycopg2.extras

logger = logging.getLogger(__name__)

# Hard-coded thresholds stored alongside the pattern record for traceability.
_PERSISTENT_THRESHOLD = 3
_CROSS_RESOURCE_THRESHOLD = 2
_REOPENED_THRESHOLD = 1
_ALGORITHM_VERSION = "1"


class PatternService:
    """Detects recurring patterns in finding lifecycle data and publishes records."""

    def detect_and_publish(
        self,
        db_conn: Any,
        scan_id: str,
        subscription_id: str,
        tenant_id: str,
    ) -> int:
        """Detect patterns for the given scan and upsert them into the patterns table.

        Returns the number of patterns upserted.
        """
        count = 0

        try:
            with db_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # 1. persistent_finding: occurrence_count >= threshold and OPEN/REOPENED
                cur.execute(
                    """
                    SELECT fl.id AS lifecycle_id
                    FROM finding_lifecycles fl
                    JOIN finding_fingerprints ff ON ff.id = fl.fingerprint_id
                    WHERE ff.tenant_id = %s
                      AND ff.subscription_id = %s
                      AND fl.state IN ('OPEN', 'REOPENED')
                      AND fl.occurrence_count >= %s
                    """,
                    (tenant_id, subscription_id, _PERSISTENT_THRESHOLD),
                )
                persistent_rows = cur.fetchall()

                # 2. cross_resource_recurrence: same rule_id >= 2 OPEN/REOPENED lifecycles
                cur.execute(
                    """
                    SELECT ff.rule_id,
                           array_agg(fl.id ORDER BY fl.id) AS lifecycle_ids,
                           COUNT(*) AS lc_count
                    FROM finding_lifecycles fl
                    JOIN finding_fingerprints ff ON ff.id = fl.fingerprint_id
                    WHERE ff.tenant_id = %s
                      AND ff.subscription_id = %s
                      AND fl.state IN ('OPEN', 'REOPENED')
                    GROUP BY ff.rule_id
                    HAVING COUNT(*) >= %s
                    """,
                    (tenant_id, subscription_id, _CROSS_RESOURCE_THRESHOLD),
                )
                cross_rows = cur.fetchall()

                # 3. reopened_finding: reopen_count >= 1 and state == REOPENED
                cur.execute(
                    """
                    SELECT fl.id AS lifecycle_id
                    FROM finding_lifecycles fl
                    JOIN finding_fingerprints ff ON ff.id = fl.fingerprint_id
                    WHERE ff.tenant_id = %s
                      AND ff.subscription_id = %s
                      AND fl.state = 'REOPENED'
                      AND fl.reopen_count >= %s
                    """,
                    (tenant_id, subscription_id, _REOPENED_THRESHOLD),
                )
                reopened_rows = cur.fetchall()

            # All detection queries finished; cursor closed. Upsert via fresh cursors
            # to avoid open-cursor overlap inside _upsert_pattern.
            for row in persistent_rows:
                _upsert_pattern(
                    db_conn,
                    pattern_type="persistent_finding",
                    lifecycle_id=row["lifecycle_id"],
                    tenant_id=tenant_id,
                    subscription_id=subscription_id,
                    scan_id=scan_id,
                    finding_ids=[],
                    threshold=_PERSISTENT_THRESHOLD,
                )
                count += 1

            for row in cross_rows:
                lifecycle_ids = row["lifecycle_ids"]
                # Publish one pattern per lifecycle so each is individually traceable.
                for lc_id in lifecycle_ids:
                    sibling_ids = [lid for lid in lifecycle_ids if lid != lc_id]
                    _upsert_pattern(
                        db_conn,
                        pattern_type="cross_resource_recurrence",
                        lifecycle_id=lc_id,
                        tenant_id=tenant_id,
                        subscription_id=subscription_id,
                        scan_id=scan_id,
                        finding_ids=sibling_ids,
                        threshold=_CROSS_RESOURCE_THRESHOLD,
                    )
                    count += 1

            for row in reopened_rows:
                _upsert_pattern(
                    db_conn,
                    pattern_type="reopened_finding",
                    lifecycle_id=row["lifecycle_id"],
                    tenant_id=tenant_id,
                    subscription_id=subscription_id,
                    scan_id=scan_id,
                    finding_ids=[],
                    threshold=_REOPENED_THRESHOLD,
                )
                count += 1

            db_conn.commit()
            logger.info(
                "Pattern detection for scan %s: %d pattern(s) upserted", scan_id, count
            )
            return count

        except Exception:
            db_conn.rollback()
            logger.error(
                "Pattern detection rolled back for scan %s", scan_id, exc_info=True
            )
            raise


def _upsert_pattern(
    db_conn: Any,
    pattern_type: str,
    lifecycle_id: int,
    tenant_id: str,
    subscription_id: str,
    scan_id: str,
    finding_ids: list,
    threshold: int,
) -> None:
    """Insert a pattern record if the (type, lifecycle, scan) combination is new."""
    with db_conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO patterns (
                pattern_type, lifecycle_id, tenant_id, subscription_id,
                scan_id, finding_ids, threshold, algorithm_version,
                created_at, updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
            ON CONFLICT ON CONSTRAINT uq_patterns_type_lifecycle_scan DO NOTHING
            """,
            (
                pattern_type,
                lifecycle_id,
                tenant_id,
                subscription_id,
                scan_id,
                json.dumps(finding_ids),
                threshold,
                _ALGORITHM_VERSION,
            ),
        )
