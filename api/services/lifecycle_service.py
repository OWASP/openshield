"""LifecycleService: applies scan outcomes to finding lifecycle state machines."""

import hashlib
import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Statuses that mean "we actively confirmed this rule was clean in the scan."
_RESOLVING_STATUSES = frozenset({"SUCCESS", "EMPTY_SUCCESS"})

# All statuses the DB constraint accepts. Any other value defaults to FAILED to
# prevent a single malformed outcome from aborting the whole lifecycle transaction.
_VALID_OUTCOME_STATUSES = frozenset(
    {
        "SUCCESS",
        "EMPTY_SUCCESS",
        "PERMISSION_DENIED",
        "TIMEOUT",
        "FAILED",
        "NOT_APPLICABLE",
    }
)


def _normalize_resource_id(resource_id: str) -> str:
    """Return a stable, lowercased, stripped version of an ARM resource ID."""
    return resource_id.strip().lower()


def _compute_fingerprint_hash(
    tenant_id: str,
    subscription_id: str,
    resource_id_normalized: str,
    rule_id: str,
    evidence_key: str,
    normalization_version: str,
) -> str:
    """Return a SHA-256 hex digest over canonical fields."""
    canonical = json.dumps(
        [
            tenant_id,
            subscription_id,
            resource_id_normalized,
            rule_id,
            evidence_key,
            normalization_version,
        ],
        separators=(",", ":"),
        sort_keys=False,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


class LifecycleService:
    """Applies scan results to the finding lifecycle state machines.

    All database work for a single apply_scan call executes inside one
    transaction. The idempotency sentinel (scan_lifecycle_applications) is
    inserted last, so a crash before commit means the operation never happened
    and can safely be retried. Any exception triggers an explicit rollback to
    leave the connection in a clean state for the next operation.
    """

    def apply_scan(
        self,
        db_conn: Any,
        scan_id: str,
        subscription_id: str,
        tenant_id: str,
        rule_outcomes: List[Dict[str, Any]],
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """Apply a completed scan's findings to the lifecycle tables.

        Args:
            db_conn: A psycopg2 connection (autocommit must be False).
            scan_id: UUID of the completed scan.
            subscription_id: Azure subscription ID.
            tenant_id: Tenant identifier for isolation.
            rule_outcomes: List of dicts with keys 'rule_id' and 'status'.
            findings: List of finding dicts with keys 'rule_id', 'resource_id',
                and optionally 'evidence_key'. Defaults to empty list.
        """
        findings = findings or []

        try:
            with db_conn.cursor() as cur:
                # --- Idempotency check ----------------------------------------
                cur.execute(
                    "SELECT scan_id FROM scan_lifecycle_applications WHERE scan_id = %s",
                    (scan_id,),
                )
                if cur.fetchone() is not None:
                    logger.info("Scan %s already applied; skipping lifecycle update", scan_id)
                    return

                # --- Write durable per-rule outcome records -------------------
                # UNIQUE(scan_id, rule_id) prevents duplicates on double-writes.
                for outcome in rule_outcomes:
                    rule_id_o = outcome.get("rule_id", "")
                    status_o = outcome.get("status", "FAILED")
                    if not rule_id_o:
                        continue
                    if status_o not in _VALID_OUTCOME_STATUSES:
                        logger.warning(
                            "Unknown outcome status %r for rule %s; defaulting to FAILED",
                            status_o,
                            rule_id_o,
                        )
                        status_o = "FAILED"
                    cur.execute(
                        """
                        INSERT INTO scan_rule_outcomes (
                            scan_id, rule_id, status, tenant_id, subscription_id,
                            inventory_boundary, started_at, completed_at
                        )
                        VALUES (%s, %s, %s, %s, %s, 'subscription', %s, NOW())
                        ON CONFLICT (scan_id, rule_id) DO NOTHING
                        """,
                        (
                            scan_id,
                            rule_id_o,
                            status_o,
                            tenant_id,
                            subscription_id,
                            outcome.get("started_at"),
                        ),
                    )

                # Build a lookup: rule_id -> outcome status
                outcome_by_rule: Dict[str, str] = {
                    o["rule_id"]: o["status"] for o in rule_outcomes if "rule_id" in o and "status" in o
                }

                # Collect rule IDs that actively confirmed a clean result. Only
                # these can trigger resolution of absent findings (fail-closed).
                resolving_rule_ids = [
                    rule_id for rule_id, status in outcome_by_rule.items() if status in _RESOLVING_STATUSES
                ]

                # Build the set of fingerprints seen in this scan.
                seen_fingerprint_keys: set = set()
                fingerprints_in_scan: List[Dict[str, Any]] = []
                for finding in findings:
                    rule_id = finding.get("rule_id", "")
                    resource_id = finding.get("resource_id", "")
                    evidence_key = finding.get("evidence_key", "")
                    resource_id_normalized = _normalize_resource_id(resource_id)
                    normalization_version = "1"

                    fp_hash = _compute_fingerprint_hash(
                        tenant_id,
                        subscription_id,
                        resource_id_normalized,
                        rule_id,
                        evidence_key,
                        normalization_version,
                    )
                    key = (rule_id, resource_id_normalized, evidence_key)
                    if key not in seen_fingerprint_keys:
                        seen_fingerprint_keys.add(key)
                        fingerprints_in_scan.append(
                            {
                                "tenant_id": tenant_id,
                                "subscription_id": subscription_id,
                                "resource_id_normalized": resource_id_normalized,
                                "rule_id": rule_id,
                                "evidence_key": evidence_key,
                                "normalization_version": normalization_version,
                                "fingerprint_hash": fp_hash,
                            }
                        )

                # --- Upsert fingerprints and lifecycles for seen findings -------
                seen_fingerprint_ids: set = set()
                for fp in fingerprints_in_scan:
                    # ON CONFLICT DO UPDATE forces RETURNING id on pre-existing rows.
                    cur.execute(
                        """
                        INSERT INTO finding_fingerprints (
                            tenant_id, subscription_id, resource_id_normalized,
                            rule_id, evidence_key, normalization_version,
                            fingerprint_version, fingerprint_hash
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, '1', %s)
                        ON CONFLICT (fingerprint_hash) DO UPDATE
                            SET fingerprint_hash = EXCLUDED.fingerprint_hash
                        RETURNING id
                        """,
                        (
                            fp["tenant_id"],
                            fp["subscription_id"],
                            fp["resource_id_normalized"],
                            fp["rule_id"],
                            fp["evidence_key"],
                            fp["normalization_version"],
                            fp["fingerprint_hash"],
                        ),
                    )
                    row = cur.fetchone()
                    fingerprint_id = row[0]
                    seen_fingerprint_ids.add(fingerprint_id)

                    cur.execute(
                        """
                        SELECT id, state, occurrence_count, reopen_count, row_version
                        FROM finding_lifecycles
                        WHERE fingerprint_id = %s
                        FOR UPDATE
                        """,
                        (fingerprint_id,),
                    )
                    lc_row = cur.fetchone()

                    if lc_row is None:
                        cur.execute(
                            """
                            INSERT INTO finding_lifecycles (
                                fingerprint_id, state, first_seen_scan_id,
                                last_seen_scan_id, occurrence_count,
                                consecutive_success_count, reopen_count, row_version
                            )
                            VALUES (%s, 'OPEN', %s, %s, 1, 0, 0, 0)
                            RETURNING id
                            """,
                            (fingerprint_id, scan_id, scan_id),
                        )
                        lifecycle_id = cur.fetchone()[0]
                        cur.execute(
                            """
                            INSERT INTO finding_lifecycle_transitions
                                (lifecycle_id, from_state, to_state, scan_id, reason)
                            VALUES (%s, NULL, 'OPEN', %s, 'New finding observed')
                            """,
                            (lifecycle_id, scan_id),
                        )
                    else:
                        lifecycle_id, state, occurrence_count, reopen_count, row_version = lc_row
                        if state in ("OPEN", "REOPENED"):
                            cur.execute(
                                """
                                UPDATE finding_lifecycles
                                SET occurrence_count = occurrence_count + 1,
                                    last_seen_scan_id = %s,
                                    updated_at = NOW(),
                                    row_version = row_version + 1
                                WHERE id = %s
                                """,
                                (scan_id, lifecycle_id),
                            )
                        elif state in ("RESOLVED", "ACCEPTED", "SUPPRESSED"):
                            cur.execute(
                                """
                                UPDATE finding_lifecycles
                                SET state = 'REOPENED',
                                    last_seen_scan_id = %s,
                                    occurrence_count = occurrence_count + 1,
                                    reopen_count = reopen_count + 1,
                                    consecutive_success_count = 0,
                                    updated_at = NOW(),
                                    row_version = row_version + 1
                                WHERE id = %s
                                """,
                                (scan_id, lifecycle_id),
                            )
                            cur.execute(
                                """
                                INSERT INTO finding_lifecycle_transitions
                                    (lifecycle_id, from_state, to_state, scan_id, reason)
                                VALUES (%s, %s, 'REOPENED', %s, 'Finding reappeared in scan')
                                """,
                                (lifecycle_id, state, scan_id),
                            )

                # --- Resolve findings NOT seen in this scan -------------------
                # Fail-closed: skip resolution entirely if no rule confirmed a
                # clean result this scan (all outcomes were FAILED/PERMISSION_DENIED).
                if resolving_rule_ids:
                    if seen_fingerprint_ids:
                        # Use != ALL(%s) with a list to avoid single-element tuple
                        # syntax issues that occur with NOT IN %s.
                        cur.execute(
                            """
                            SELECT fl.id, fl.state, fl.row_version, ff.rule_id
                            FROM finding_lifecycles fl
                            JOIN finding_fingerprints ff ON ff.id = fl.fingerprint_id
                            WHERE ff.tenant_id = %s
                              AND ff.subscription_id = %s
                              AND fl.state IN ('OPEN', 'REOPENED')
                              AND fl.fingerprint_id != ALL(%s)
                              AND ff.rule_id = ANY(%s)
                            FOR UPDATE OF fl
                            """,
                            (
                                tenant_id,
                                subscription_id,
                                list(seen_fingerprint_ids),
                                resolving_rule_ids,
                            ),
                        )
                    else:
                        cur.execute(
                            """
                            SELECT fl.id, fl.state, fl.row_version, ff.rule_id
                            FROM finding_lifecycles fl
                            JOIN finding_fingerprints ff ON ff.id = fl.fingerprint_id
                            WHERE ff.tenant_id = %s
                              AND ff.subscription_id = %s
                              AND fl.state IN ('OPEN', 'REOPENED')
                              AND ff.rule_id = ANY(%s)
                            FOR UPDATE OF fl
                            """,
                            (tenant_id, subscription_id, resolving_rule_ids),
                        )
                    _resolve_absent_rows(cur, scan_id, outcome_by_rule)

                # --- Idempotency sentinel (inserted last) ---------------------
                cur.execute(
                    """
                    INSERT INTO scan_lifecycle_applications (scan_id, applied_by)
                    VALUES (%s, 'system')
                    """,
                    (scan_id,),
                )

            db_conn.commit()
            logger.info("Lifecycle application committed for scan %s", scan_id)

        except Exception:
            db_conn.rollback()
            logger.error("Lifecycle application rolled back for scan %s", scan_id, exc_info=True)
            raise


def _resolve_absent_rows(
    cur: Any,
    scan_id: str,
    outcome_by_rule: Dict[str, str],
) -> None:
    """Transition OPEN/REOPENED lifecycle rows to RESOLVED for clean-outcome rules.

    The SQL query already filters by resolving_rule_ids, so outcome_status is
    always in _RESOLVING_STATUSES here. The check is kept as a defensive guard.
    """
    absent_rows = cur.fetchall()
    for lc_id, state, row_version, rule_id in absent_rows:
        outcome_status = outcome_by_rule.get(rule_id)
        if outcome_status in _RESOLVING_STATUSES:
            cur.execute(
                """
                UPDATE finding_lifecycles
                SET state = 'RESOLVED',
                    last_seen_scan_id = %s,
                    consecutive_success_count = consecutive_success_count + 1,
                    updated_at = NOW(),
                    row_version = row_version + 1
                WHERE id = %s
                """,
                (scan_id, lc_id),
            )
            cur.execute(
                """
                INSERT INTO finding_lifecycle_transitions
                    (lifecycle_id, from_state, to_state, scan_id, reason)
                VALUES (%s, %s, 'RESOLVED', %s,
                        'Rule confirmed clean; finding absent from scan')
                """,
                (lc_id, state, scan_id),
            )
