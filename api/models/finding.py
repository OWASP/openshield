"""Finding dataclass and PostgreSQL-backed DatabaseManager."""

import hashlib
import json
import logging
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras
import psycopg2.pool

from openshield.severity import (
    CONTRACT_VERSION,
    normalize_severity,
    score_counts,
    score_findings,
    severity_rank,
)
from scanner.evaluation import EvaluationStatus

logger = logging.getLogger(__name__)

FRAMEWORKS_DIR = Path(__file__).parent.parent.parent / "compliance" / "frameworks"

# One pool per DSN, shared across all DatabaseManager instances in this
# process. Routes create a new DatabaseManager per request, but they all
# borrow from the same small set of long-lived connections instead of
# opening a fresh PostgreSQL connection on every request.
_POOLS: Dict[str, "psycopg2.pool.ThreadedConnectionPool"] = {}
_POOLS_LOCK = threading.Lock()


_POOL_MAX_CONN = int(os.environ.get("DB_POOL_MAX_CONN", "10"))


def _get_pool(dsn: str) -> "psycopg2.pool.ThreadedConnectionPool":
    # Pool creation happens at most once per DSN per process lifetime, so a
    # plain lock (no unlocked fast path) is simpler and just as cheap here.
    with _POOLS_LOCK:
        pool = _POOLS.get(dsn)
        if pool is None:
            pool = psycopg2.pool.ThreadedConnectionPool(1, _POOL_MAX_CONN, dsn)
            _POOLS[dsn] = pool
        return pool


def get_pool_stats(dsn: Optional[str] = None) -> Dict[str, Any]:
    """Return a point-in-time snapshot of the shared connection pool's utilization.

    Reports only counts (in-use / idle / configured maximum) - never the DSN,
    host, credentials, or anything else that could describe the database
    deployment. Safe to expose on a public surface (Prometheus /metrics, the
    /ready probe) precisely because it carries no operational secrets, only
    capacity numbers an operator needs to see the pool approaching exhaustion
    before it happens.

    Returns zeroed stats with no pool created yet (no request has connected
    since process start) rather than raising, so callers on the request path
    (like /ready) never fail because of a stats lookup.
    """
    dsn = dsn or os.environ.get("DATABASE_URL", "")
    with _POOLS_LOCK:
        pool = _POOLS.get(dsn)

    if pool is None:
        return {"max_connections": _POOL_MAX_CONN, "in_use": 0, "idle": 0, "utilization_percent": 0.0}

    # psycopg2's pool has no public stats API; _used/_pool/maxconn are the
    # same attributes getconn()/putconn() themselves mutate under this same
    # lock, so a snapshot taken while holding it can't land mid-mutation.
    with pool._lock:
        in_use = len(pool._used)
        idle = len(pool._pool)
        max_connections = pool.maxconn

    utilization_percent = round((in_use / max_connections) * 100, 1) if max_connections else 0.0
    return {
        "max_connections": max_connections,
        "in_use": in_use,
        "idle": idle,
        "utilization_percent": utilization_percent,
    }


FRAMEWORK_FILE_MAP = {
    "cis": "cis_azure_benchmark.json",
    "nist": "nist_csf.json",
    "iso27001": "iso27001.json",
    "soc2": "soc2.json",
    "ncsc_pqc": "ncsc_pqc.json",
    "enisa_pqc": "enisa_pqc.json",
}

_PACK_METADATA_KEYS = (
    "framework",
    "version",
    "mapping_pack_version",
    "mapping_pack_status",
    "mapping_pack_source",
    "mapping_pack_published",
)

# Reserved key holding a full snapshot's content hash, alongside the
# human-maintained mapping_pack_version. The semver is only bumped when a
# maintainer remembers to; the hash catches a controls change regardless.
_CONTENT_HASH_KEY = "mapping_pack_content_hash"


def _compute_mapping_pack_content_hash(controls: Dict[str, Any]) -> str:
    """A stable hash of a framework's controls dict.

    Used both to detect a mapping-pack revision that didn't bump
    mapping_pack_version, and to verify a stored snapshot was not corrupted
    or partially overwritten before get_compliance_score() trusts it as the
    historically accurate mapping for a scan.
    """
    canonical = json.dumps(controls, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _build_compliance_mapping_snapshot() -> Dict[str, Any]:
    """Capture each framework's complete mapping — not just its metadata — at
    the moment a scan is saved.

    Historical scans must remain interpretable even after the mapping pack on
    disk is later revised or a framework edition is superseded. Snapshotting
    metadata alone was not enough for that: get_compliance_score() also needs
    the exact controls, mapping types, and denominator membership that were
    in effect for this scan, or a mapping-pack update after the scan would
    silently reclassify it under the new pack while still claiming the old
    pack's provenance. So this snapshot captures the full controls dict per
    framework, plus a content hash for integrity verification, and is what a
    report for this scan prefers over the live files.

    A framework file that is missing or unreadable does not fail the scan
    save (a transient read error on one framework must not block persisting
    the scan itself), but the failure is never silent: it's logged, and
    recorded under the reserved "_capture_errors" key in the returned dict
    so a consumer reading this exact snapshot later (get_compliance_score())
    can tell "this framework's provenance was never captured" apart from
    "this framework simply wasn't configured" — and must not quietly fall
    back to live mapping data while still claiming historical accuracy.
    """
    snapshot: Dict[str, Any] = {}
    capture_errors: Dict[str, str] = {}
    for framework, filename in FRAMEWORK_FILE_MAP.items():
        try:
            with open(FRAMEWORKS_DIR / filename) as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("compliance mapping snapshot: could not capture %s (%s): %s", framework, filename, exc)
            capture_errors[framework] = f"{type(exc).__name__}: {exc}"
            continue
        controls = data.get("controls", {})
        snapshot[framework] = {
            **{key: data.get(key) for key in _PACK_METADATA_KEYS},
            "controls": controls,
            _CONTENT_HASH_KEY: _compute_mapping_pack_content_hash(controls),
        }
    if capture_errors:
        snapshot["_capture_errors"] = capture_errors
    return snapshot


@dataclass
class Finding:
    """Represents a single security misconfiguration finding."""

    rule_id: str
    rule_name: str
    severity: str
    category: str
    resource_id: str
    resource_name: str
    resource_type: str
    description: str
    remediation: str
    frameworks: Dict[str, str]
    detected_at: str
    scan_id: Optional[str] = None
    playbook: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    cve_references: List[Dict[str, Any]] = field(default_factory=list)
    cvss_score: Optional[float] = None
    exploit_available: bool = False
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "category": self.category,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "resource_type": self.resource_type,
            "description": self.description,
            "remediation": self.remediation,
            "frameworks": self.frameworks,
            "detected_at": self.detected_at,
            "scan_id": self.scan_id,
            "playbook": self.playbook,
            "metadata": self.metadata,
            "cve_references": self.cve_references,
            "cvss_score": self.cvss_score,
            "exploit_available": self.exploit_available,
        }


class DatabaseManager:
    """Manages PostgreSQL persistence for scans, findings, and scoring.

    Database operations open a new connection on first use. Call connect()
    explicitly to pre-warm the connection.
    """

    def __init__(self, dsn: Optional[str] = None) -> None:
        self.dsn = dsn or os.environ["DATABASE_URL"]
        self.conn: Optional[Any] = None

    # ------------------------------------------------------------------ #
    # Connection                                                            #
    # ------------------------------------------------------------------ #

    def connect(self) -> None:
        """Acquire a connection from this DSN's shared pool."""
        self.conn = _get_pool(self.dsn).getconn()
        self.conn.autocommit = False
        logger.debug("Database connection acquired from pool")

    def _get_conn(self) -> Any:
        if self.conn is None or self.conn.closed:
            self.connect()
        return self.conn

    def close(self) -> None:
        """Return the connection to its pool (or discard it if broken)."""
        if self.conn is None:
            return
        try:
            _get_pool(self.dsn).putconn(self.conn, close=bool(self.conn.closed))
            logger.debug("Database connection returned to pool")
        except Exception as exc:
            logger.error("Error returning connection to pool: %s", exc)
        finally:
            self.conn = None

    def ping(self) -> bool:
        """Execute a trivial query to confirm database connectivity.

        Used by the /ready probe. Raises on failure so the caller can map it
        to a 503; returns True when the database answers.
        """
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        return True

    def init_db(self) -> None:
        """Deprecated compatibility hook; schema changes are managed by Alembic."""
        logger.warning(
            "DatabaseManager.init_db() is deprecated and no longer manages the schema; "
            "run 'alembic upgrade head' instead"
        )

    # ------------------------------------------------------------------ #
    # Write                                                                 #
    # ------------------------------------------------------------------ #

    def save_scan(self, scan_result: Dict[str, Any]) -> None:
        """Persist a full scan result (scan header + all findings)."""
        from datetime import datetime, timezone

        # Validate and canonicalize the entire batch before issuing SQL. A bad
        # severity must never be stored with a zero/default weight.
        findings = []
        for raw_finding in scan_result.get("findings", []):
            finding = dict(raw_finding)
            finding["severity"] = normalize_severity(finding.get("severity"))
            findings.append(finding)

        conn = self._get_conn()
        completed_at = scan_result.get("completed_at") or datetime.now(timezone.utc).isoformat()
        mapping_snapshot_dict = _build_compliance_mapping_snapshot()
        # Rules the scan engine could not complete (raised, or returned
        # malformed data) are recorded alongside the mapping-pack snapshot so
        # get_compliance_score() can exclude them from PASS instead of
        # reading their absence from findings as a clean result. This is a
        # stopgap ahead of issue #263's persisted per-resource evaluation
        # table - it only knows "this rule did not complete for this scan",
        # not per-resource outcomes.
        failed_rule_ids = scan_result.get("failed_rule_ids") or []
        if failed_rule_ids:
            mapping_snapshot_dict["_scan_rule_outcomes"] = {"failed_rule_ids": sorted(set(failed_rule_ids))}
        mapping_snapshot = json.dumps(mapping_snapshot_dict)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO scans (
                        scan_id, subscription_id, started_at, completed_at,
                        total_findings, score, cve_enrichment_status, status,
                        attempt_count, error_message, severity_contract_version,
                        compliance_mapping_snapshot
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (scan_id) DO UPDATE SET
                        completed_at = EXCLUDED.completed_at,
                        total_findings = EXCLUDED.total_findings,
                        score = EXCLUDED.score,
                        status = EXCLUDED.status,
                        error_message = EXCLUDED.error_message,
                        severity_contract_version = EXCLUDED.severity_contract_version,
                        -- The mapping-pack provenance captured for a scan_id's
                        -- first successful write is its historical record and
                        -- must stay immutable on replay (e.g. a worker retry
                        -- that reuses the same scan_id) - only fill it in if
                        -- this scan_id never captured one. But
                        -- _scan_rule_outcomes is per-attempt execution state,
                        -- not provenance: it always has to reflect the
                        -- findings actually being written by *this* save, so
                        -- it's re-merged from EXCLUDED on every write rather
                        -- than being frozen by the COALESCE along with the
                        -- rest of the snapshot - otherwise a rule that failed
                        -- on attempt 1 and succeeded on a retry would keep
                        -- reading as NOT_EVALUATED forever (or the reverse).
                        compliance_mapping_snapshot = COALESCE(
                            scans.compliance_mapping_snapshot, EXCLUDED.compliance_mapping_snapshot
                        ) || jsonb_build_object(
                            '_scan_rule_outcomes', EXCLUDED.compliance_mapping_snapshot -> '_scan_rule_outcomes'
                        )
                    """,
                    (
                        scan_result["scan_id"],
                        scan_result["subscription_id"],
                        scan_result["started_at"],
                        completed_at,
                        len(findings),
                        score_findings(findings),
                        scan_result.get("cve_enrichment_status", "PENDING"),
                        scan_result.get("status", "completed"),
                        scan_result.get("attempt_count", 0),
                        scan_result.get("error_message"),
                        CONTRACT_VERSION,
                        mapping_snapshot,
                    ),
                )
                # A worker retry replaces the previous result atomically. This
                # keeps the scan header, child rows, and recomputed score in
                # agreement instead of duplicating findings on every attempt.
                cur.execute("DELETE FROM findings WHERE scan_id = %s", (scan_result["scan_id"],))
                finding_id_by_key: Dict[Any, int] = {}
                for f in findings:
                    cur.execute(
                        """
                        INSERT INTO findings
                            (scan_id, rule_id, rule_name, severity, category,
                             resource_id, resource_name, resource_type,
                             description, remediation, playbook,
                             frameworks, metadata, cve_references,
                             cvss_score, exploit_available, detected_at)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        RETURNING id
                        """,
                        (
                            # The parent scan owns every child in this batch.
                            # Never trust a caller-supplied child scan_id.
                            scan_result["scan_id"],
                            f.get("rule_id"),
                            f.get("rule_name"),
                            f.get("severity"),
                            f.get("category"),
                            f.get("resource_id"),
                            f.get("resource_name"),
                            f.get("resource_type"),
                            f.get("description"),
                            f.get("remediation"),
                            f.get("playbook"),
                            json.dumps(f.get("frameworks", {})),
                            json.dumps(f.get("metadata", {})),
                            json.dumps(f.get("cve_references", [])),
                            f.get("cvss_score"),
                            f.get("exploit_available", False),
                            f.get("detected_at"),
                        ),
                    )
                    finding_id_by_key[(f.get("rule_id"), f.get("resource_id"))] = cur.fetchone()[0]

                # Coverage rows (#263): a status for every resource a migrated
                # rule looked at, not just its violations. A FAIL evaluation
                # is durably linked to the finding row it corresponds to
                # right here, in the same transaction, instead of leaving
                # callers to infer the relationship from rule_id/resource_id.
                #
                # Upserted rather than replaced wholesale: a retried/replayed
                # scan result must converge on the same rows instead of a
                # delete-then-reinsert racing a concurrent reader that could
                # briefly see zero coverage for a scan that already has some.
                evaluated_at = completed_at
                evaluations = scan_result.get("evaluations", [])
                for evaluation in evaluations:
                    status = evaluation.get("status")
                    finding_id = None
                    if status == EvaluationStatus.FAIL:
                        finding_id = finding_id_by_key.get((evaluation.get("rule_id"), evaluation.get("resource_id")))
                    cur.execute(
                        """
                        INSERT INTO rule_evaluations
                            (scan_id, rule_id, resource_id, resource_type, status,
                             reason_code, reason, evidence, finding_id, evaluated_at)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (scan_id, rule_id, resource_id) DO UPDATE SET
                            resource_type = EXCLUDED.resource_type,
                            status = EXCLUDED.status,
                            reason_code = EXCLUDED.reason_code,
                            reason = EXCLUDED.reason,
                            evidence = EXCLUDED.evidence,
                            finding_id = EXCLUDED.finding_id,
                            evaluated_at = EXCLUDED.evaluated_at
                        """,
                        (
                            scan_result["scan_id"],
                            evaluation.get("rule_id"),
                            evaluation.get("resource_id"),
                            evaluation.get("resource_type") or "",
                            status,
                            evaluation.get("reason_code"),
                            evaluation.get("reason"),
                            json.dumps(evaluation.get("evidence", {})),
                            finding_id,
                            evaluated_at,
                        ),
                    )

                # A rule/resource that no longer appears (a rule removed from
                # this scan's set, a resource that's gone) must not leave a
                # stale coverage row behind once the current set is upserted.
                if evaluations:
                    cur.execute(
                        """
                        DELETE FROM rule_evaluations
                        WHERE scan_id = %s
                          AND (rule_id, resource_id) NOT IN (
                              SELECT * FROM unnest(%s::text[], %s::text[])
                          )
                        """,
                        (
                            scan_result["scan_id"],
                            [evaluation.get("rule_id") for evaluation in evaluations],
                            [evaluation.get("resource_id") for evaluation in evaluations],
                        ),
                    )
                else:
                    cur.execute("DELETE FROM rule_evaluations WHERE scan_id = %s", (scan_result["scan_id"],))
            conn.commit()
        except Exception:
            # psycopg2 connections remain in an aborted transaction after any
            # SQL error. Roll back here so the worker can record failure and
            # safely process subsequent scans on the same pooled connection.
            conn.rollback()
            raise
        logger.info(
            "Saved scan %s with %d findings",
            scan_result["scan_id"],
            len(findings),
        )

    # ------------------------------------------------------------------ #
    # Read                                                                  #
    # ------------------------------------------------------------------ #

    def get_findings(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Return findings, optionally filtered by severity, category, or rule_id."""
        filters = filters or {}
        severity = filters.get("severity")
        severity = normalize_severity(severity) if severity is not None else None
        category = filters.get("category")
        rule_id = filters.get("rule_id")
        scan_id = filters.get("scan_id")

        sql = """
            SELECT * FROM findings
            WHERE (%s IS NULL OR severity = %s)
              AND (%s IS NULL OR LOWER(category) = LOWER(%s))
              AND (%s IS NULL OR rule_id = %s)
              AND scan_id = COALESCE(
                  %s,
                  (SELECT scan_id FROM scans WHERE status = 'completed' ORDER BY started_at DESC LIMIT 1)
              )
            ORDER BY detected_at DESC
            LIMIT 1000
        """
        params = (severity, severity, category, category, rule_id, rule_id, scan_id)

        conn = self._get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]

    def get_finding_by_id(self, finding_id: int) -> Optional[Dict[str, Any]]:
        """Return a single finding by its integer primary key."""
        conn = self._get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM findings WHERE id = %s", (finding_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_latest_completed_scan(self) -> Optional[Dict[str, Any]]:
        """Return the most recently started completed scan."""
        conn = self._get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT * FROM scans
                WHERE status = 'completed'
                ORDER BY started_at DESC
                LIMIT 1
                """
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def update_cve_fields(self, findings: List[Dict[str, Any]]) -> None:
        """Persist CVE enrichment fields for existing findings.

        Updates are no-ops for findings without an id.
        """
        if not findings:
            return

        conn = self._get_conn()
        with conn.cursor() as cur:
            for f in findings:
                finding_id = f.get("id")
                if not finding_id:
                    continue
                cur.execute(
                    """
                    UPDATE findings
                    SET cve_references = %s,
                        cvss_score = %s,
                        exploit_available = %s
                    WHERE id = %s
                    """,
                    (
                        json.dumps(f.get("cve_references", [])),
                        f.get("cvss_score"),
                        f.get("exploit_available", False),
                        finding_id,
                    ),
                )
        conn.commit()

    def update_scan_enrichment_status(self, scan_id: str, status: str) -> None:
        """Update the CVE enrichment status for a specific scan."""
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE scans SET cve_enrichment_status = %s WHERE scan_id = %s",
                (status, scan_id),
            )
        conn.commit()
        logger.info("Updated scan %s enrichment status to %s", scan_id, status)

    def create_pending_scan(self, scan_id: str, subscription_id: str) -> None:
        """Create a scan record in the 'pending' state."""
        conn = self._get_conn()
        from datetime import datetime, timezone

        started_at = datetime.now(timezone.utc).isoformat()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scans (scan_id, subscription_id, started_at, status, attempt_count)
                VALUES (%s, %s, %s, 'pending', 0)
                """,
                (scan_id, subscription_id, started_at),
            )
        conn.commit()
        logger.info("Created pending scan %s for %s", scan_id, subscription_id)

    def update_scan_status(self, scan_id: str, status: str, error_message: Optional[str] = None) -> None:
        """Update the status of a scan (running, completed, failed)."""
        conn = self._get_conn()
        from datetime import datetime, timezone

        with conn.cursor() as cur:
            if status == "completed":
                completed_at = datetime.now(timezone.utc).isoformat()
                cur.execute(
                    "UPDATE scans SET status = %s, completed_at = %s, error_message = NULL WHERE scan_id = %s",
                    (status, completed_at, scan_id),
                )
            else:
                cur.execute(
                    "UPDATE scans SET status = %s, error_message = %s WHERE scan_id = %s",
                    (status, error_message, scan_id),
                )
        conn.commit()
        logger.info("Updated scan %s status to %s", scan_id, status)

    def claim_next_pending_scan(self) -> Optional[Dict[str, Any]]:
        """Atomically claim the next pending scan using SKIP LOCKED."""
        conn = self._get_conn()
        from datetime import datetime, timezone

        claimed_at = datetime.now(timezone.utc).isoformat()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                UPDATE scans
                SET status = 'running',
                    claimed_at = %s,
                    attempt_count = COALESCE(attempt_count, 0) + 1,
                    error_message = NULL
                WHERE scan_id = (
                    SELECT scan_id
                    FROM scans
                    WHERE status = 'pending'
                    ORDER BY started_at ASC
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                )
                RETURNING *
                """,
                (claimed_at,),
            )
            row = cur.fetchone()
            if row:
                conn.commit()
                return dict(row)
            return None

    def recover_stale_scans(self, timeout_minutes: int = 60, max_attempts: int = 3) -> int:
        """Recover scans left running after a worker crash or restart.

        Stale scans are returned to pending while retry attempts remain. Once a
        scan has reached max_attempts, it is marked failed so it cannot loop
        forever on bad credentials or persistent Azure errors.
        """
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scans
                SET status = 'failed',
                    error_message = 'Scan exceeded maximum retry attempts after worker interruption.'
                WHERE status = 'running'
                  AND COALESCE(attempt_count, 1) >= %s
                  AND claimed_at < (CURRENT_TIMESTAMP - (%s * INTERVAL '1 minute'))
                """,
                (max_attempts, timeout_minutes),
            )
            failed_count = cur.rowcount

            cur.execute(
                """
                UPDATE scans
                SET status = 'pending',
                    claimed_at = NULL,
                    error_message = 'Scan worker interrupted before completion. Queued for retry.'
                WHERE status = 'running'
                  AND COALESCE(attempt_count, 0) < %s
                  AND claimed_at < (CURRENT_TIMESTAMP - (%s * INTERVAL '1 minute'))
                """,
                (max_attempts, timeout_minutes),
            )
            retry_count = cur.rowcount
        conn.commit()
        total_count = failed_count + retry_count
        if total_count > 0:
            logger.info(
                "Recovered %d stale 'running' scans (%d retried, %d failed)",
                total_count,
                retry_count,
                failed_count,
            )
        return total_count

    def get_pending_scans(self) -> List[Dict[str, Any]]:
        """Return all scans in the 'pending' state."""
        conn = self._get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM scans WHERE status = 'pending' ORDER BY started_at ASC")
            return [dict(row) for row in cur.fetchall()]

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Return a single scan record by its UUID."""
        conn = self._get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM scans WHERE scan_id = %s", (scan_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_scans(self) -> List[Dict[str, Any]]:
        """Return all scan records ordered by most recent first."""
        conn = self._get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM scans ORDER BY started_at DESC LIMIT 100")
            return [dict(row) for row in cur.fetchall()]

    # ------------------------------------------------------------------ #
    # Scoring                                                               #
    # ------------------------------------------------------------------ #

    def get_score(self) -> Dict[str, Any]:
        """Return a 0-100 security posture score based on the latest scan's findings.

        Scoped to the most recent scan so historical findings from older scans
        do not accumulate and drive the score to zero.
        CRITICAL findings deduct 20 points each, HIGH 10, MEDIUM 5,
        LOW 2, and INFO 0 (openshield.severity.score_counts). Floors at 0.

        The scan-existence check is a separate query from the findings lookup:
        folding both into one `scan_id = (SELECT ...)` subquery (the previous
        approach) cannot distinguish "no completed scan exists" from "the
        latest completed scan found nothing" - both yield zero rows, so the
        former was silently reported as a perfect 100 score with no actual
        evidence behind it, the same NO_SCAN_DATA gap fixed in
        get_compliance_score().

        Returns:
            {"status": "NO_SCAN_DATA", "score": None, "message": ...} when no
            completed scan exists yet, or {"status": "OK", "score": <0-100>}
            once one has.
        """
        subscription_id = getattr(self, "subscription_id", None)
        conn = self._get_conn()
        with conn.cursor() as cur:
            if subscription_id:
                cur.execute(
                    "SELECT scan_id FROM scans "
                    "WHERE status = 'completed' AND subscription_id = %s "
                    "ORDER BY started_at DESC LIMIT 1",
                    (subscription_id,),
                )
            else:
                cur.execute("SELECT scan_id FROM scans WHERE status = 'completed' ORDER BY started_at DESC LIMIT 1")
            latest_scan = cur.fetchone()

            if latest_scan is None:
                return {
                    "status": "NO_SCAN_DATA",
                    "score": None,
                    "max_score": 100,
                    "message": ("No completed scan is available yet, so there is no security posture to score."),
                }

            scan_id = latest_scan[0]
            cur.execute("SELECT severity, COUNT(*) FROM findings WHERE scan_id = %s GROUP BY severity", (scan_id,))
            rows = cur.fetchall()

        score = score_counts({severity: count for severity, count in rows})
        return {"status": "OK", "score": score, "max_score": 100}

    def get_cve_summary(self) -> Dict[str, Any]:
        """Return high-level summary of CVE findings for the dashboard."""
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    s.cve_enrichment_status,
                    COUNT(f.*) as total_findings,
                    COUNT(CASE WHEN f.exploit_available = TRUE THEN 1 END) as exploit_count,
                    MAX(f.cvss_score) as max_cvss_score,
                    AVG(f.cvss_score) as avg_cvss_score,
                    COUNT(CASE WHEN f.cvss_score >= 9.0 THEN 1 END) as critical_cve_count
                FROM scans s
                LEFT JOIN findings f ON s.scan_id = f.scan_id
                WHERE s.scan_id = (
                    SELECT scan_id FROM scans WHERE status = 'completed' ORDER BY started_at DESC LIMIT 1
                )
                GROUP BY s.cve_enrichment_status
            """)
            row = cur.fetchone()

        if not row:
            return {
                "status": "UNKNOWN",
                "total_findings": 0,
                "exploit_count": 0,
                "max_cvss_score": None,
                "avg_cvss_score": None,
                "critical_cve_count": 0,
            }

        return {
            "status": row[0],
            "total_findings": row[1],
            "exploit_count": row[2],
            "max_cvss_score": row[3],
            "avg_cvss_score": round(row[4], 2) if row[4] is not None else None,
            "critical_cve_count": row[5],
        }

    def get_compliance_score(self, framework: str, subscription_id: Optional[str] = None) -> Dict[str, Any]:
        """Return technical-evidence coverage against a compliance framework mapping pack.

        This reports coverage from the most recent completed scan, not a
        certification or a claim of full framework compliance. Controls whose
        mapping_type is "not_applicable" or "organizational" are listed but
        excluded from the pass-rate denominator (score_percent), because a
        technical scan cannot itself establish an organizational control or a
        control the mapped framework edition does not define.

        Args:
            framework: One of the keys in FRAMEWORK_FILE_MAP (e.g. 'cis', 'nist').
            subscription_id: When given, scopes the "latest completed scan"
                lookup to this subscription. In a shared-database deployment
                that stores scans for more than one Azure subscription,
                omitting this returns whichever subscription scanned most
                recently - not this caller's own data.

        Returns:
            dict with keys: framework, version, mapping_pack_version,
            mapping_pack_status, mapping_pack_source, mapping_pack_published,
            evaluation_basis, total_controls, in_scope_controls,
            excluded_controls, passed, failed, score_percent, controls (list
            of control detail objects each carrying mapping_type, evidence_type,
            primary_source, rationale, owner, review_status, review_date).
        """
        filename = FRAMEWORK_FILE_MAP.get(framework.lower())
        if not filename:
            return {"error": f"Unknown framework: {framework}"}

        framework_path = FRAMEWORKS_DIR / filename
        if not framework_path.exists():
            return {"error": f"Framework file not found: {filename}"}

        with open(framework_path) as fh:
            framework_data = json.load(fh)

        controls = framework_data.get("controls", {})
        pack_meta = {key: framework_data.get(key) for key in _PACK_METADATA_KEYS}
        # Present regardless of provenance, so callers never have to branch
        # on whether this came from a snapshot to find the hash field.
        pack_meta[_CONTENT_HASH_KEY] = _compute_mapping_pack_content_hash(controls)

        # Finding detail (severity/category/resource count) still comes from
        # findings — evaluations don't carry severity. Pass/fail/unknown/error
        # status comes from rule_evaluations, so a rule that was never run,
        # errored, or hasn't been migrated to evaluate() yet is never silently
        # reported as PASS just because it produced no findings (#263).
        conn = self._get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if subscription_id:
                cur.execute(
                    "SELECT scan_id, compliance_mapping_snapshot FROM scans "
                    "WHERE status = 'completed' AND subscription_id = %s ORDER BY started_at DESC LIMIT 1",
                    (subscription_id,),
                )
            else:
                cur.execute(
                    "SELECT scan_id, compliance_mapping_snapshot FROM scans "
                    "WHERE status = 'completed' ORDER BY started_at DESC LIMIT 1"
                )
            latest_scan = cur.fetchone()

            if latest_scan is None:
                # No completed scan exists yet: there is no evidence to report.
                # Absence of findings must never be presented as a passing score.
                # in_scope_controls/excluded_controls/passed/failed are None
                # here, not 0 - a literal 0 would read as "this mapping pack
                # has zero in-scope controls" (the real, distinct
                # NO_IN_SCOPE_CONTROLS case below), when what's actually true
                # is that scope has not been determined yet because nothing
                # has run. total_controls is still meaningful (the pack
                # defines this many controls); the others are not.
                return {
                    **pack_meta,
                    "status": "NO_SCAN_DATA",
                    "message": (
                        "No completed scan is available yet, so no technical "
                        "evidence exists to report against this framework."
                    ),
                    "evaluation_basis": (
                        "No completed scan exists yet, so no control below could be "
                        "evaluated. in_scope_controls/excluded_controls/passed/failed "
                        "are null, not 0 - this is distinct from a scan that completed "
                        "and found zero in-scope controls (status NO_IN_SCOPE_CONTROLS)."
                    ),
                    "total_controls": len(controls),
                    "in_scope_controls": None,
                    "excluded_controls": None,
                    "passed": None,
                    "failed": None,
                    "score_percent": None,
                    "controls": [],
                }

            scan_id = latest_scan["scan_id"]
            snapshot = latest_scan.get("compliance_mapping_snapshot") or {}
            snapshot_for_fw = snapshot.get(framework.lower())
            if snapshot_for_fw and isinstance(snapshot_for_fw.get("controls"), dict):
                # A full historical snapshot exists: reproduce the exact
                # controls, mapping types, and denominator membership that
                # were in effect for this scan, not whatever is on disk now.
                # Otherwise a mapping-pack update after the scan would
                # silently re-evaluate it under the new pack while this
                # response still claimed the old pack's provenance.
                controls = snapshot_for_fw["controls"]
                stored_hash = snapshot_for_fw.get(_CONTENT_HASH_KEY)
                if not stored_hash:
                    # No content hash was ever captured for this snapshot
                    # (e.g. saved before the hash field shipped) - integrity
                    # was never checked, so this must not be labelled plain
                    # "snapshot", which would imply a verification that
                    # never happened.
                    mapping_provenance = "snapshot_no_hash"
                elif stored_hash != _compute_mapping_pack_content_hash(controls):
                    # The stored snapshot no longer hashes to what it claims -
                    # corrupted or partially overwritten. Still the best
                    # historical data available, but must not be presented as
                    # a clean, verified snapshot.
                    logger.error(
                        "compliance mapping snapshot for scan %s framework %s failed integrity "
                        "check: stored hash does not match its own controls",
                        scan_id,
                        framework.lower(),
                    )
                    mapping_provenance = "snapshot_hash_mismatch"
                else:
                    mapping_provenance = "snapshot"
                pack_meta = {key: snapshot_for_fw.get(key) for key in _PACK_METADATA_KEYS}
                pack_meta[_CONTENT_HASH_KEY] = stored_hash
            elif snapshot_for_fw:
                # Legacy snapshot: metadata was captured historically but the
                # full controls were not (scan saved before this snapshot was
                # widened to include them). The denominator/classification
                # below still has to come from whatever mapping is on disk
                # now, so this must not be labelled "snapshot" - that would
                # claim a historical accuracy this response doesn't have.
                pack_meta = snapshot_for_fw
                mapping_provenance = "live_fallback_legacy_snapshot"
            elif framework.lower() in (snapshot.get("_capture_errors") or {}):
                # The snapshot was attempted for this exact scan and this exact
                # framework, and it failed (logged at save time - see
                # _build_compliance_mapping_snapshot). Falling back to whatever
                # mapping pack happens to be on disk *now* is the only option
                # left, but it must never be presented as if it were the
                # historically accurate provenance for this scan.
                mapping_provenance = "live_fallback_capture_failed"
            else:
                # No snapshot entry and no recorded capture error for this
                # framework - a benign case (e.g. a scan saved before this
                # framework existed, or before the snapshot feature shipped).
                mapping_provenance = "live_fallback_no_snapshot"

        # A separate, plain (non-RealDict) cursor for this one - its rows are
        # unpacked positionally below, and a RealDictCursor row is a plain
        # OrderedDict with no __iter__ override, so `a, b, c, d = row` would
        # silently unpack its *keys* ("rule_id", "severity", ...) rather than
        # their values instead of failing loudly.
        with conn.cursor() as cur2:
            # Grouped by severity/category too (not just DISTINCT rule_id) so
            # each failing control can report which severity/category/how many
            # resources are affected, not just a bare FAIL.
            cur2.execute(
                """
                SELECT rule_id, severity, category, COUNT(*)
                FROM findings
                WHERE scan_id = %s
                GROUP BY rule_id, severity, category
                """,
                (scan_id,),
            )
            finding_rows = cur2.fetchall()

        failures: Dict[str, Dict[str, Any]] = {}
        for rule_id, raw_severity, category, resource_count in finding_rows:
            severity = normalize_severity(raw_severity)
            current = failures.get(rule_id)
            if current is None:
                failures[rule_id] = {
                    "severity": severity,
                    "category": category,
                    "resources": resource_count,
                }
                continue
            current["resources"] += resource_count
            if severity_rank(severity) > severity_rank(current["severity"]):
                current["severity"] = severity
                current["category"] = category

        # Rules the scan engine could not complete for this scan (raised,
        # or returned malformed data) - recorded by save_scan() alongside
        # the mapping snapshot. A rule missing from findings only proves
        # a PASS when it's not also in this set; otherwise its absence
        # from findings means "never actually ran", not "ran and found
        # nothing" (issue #302/#263).
        unevaluated_rule_ids = set((snapshot.get("_scan_rule_outcomes") or {}).get("failed_rule_ids") or [])

        results = []
        excluded_count = 0
        for rule_id, control in controls.items():
            mapping_type = control.get("mapping_type", "supporting")
            is_excluded = mapping_type in ("not_applicable", "organizational")
            failure = failures.get(rule_id)
            if is_excluded:
                status = EvaluationStatus.NOT_APPLICABLE if mapping_type == "not_applicable" else "ORGANIZATIONAL"
                excluded_count += 1
            elif rule_id in unevaluated_rule_ids:
                # The rule that would provide this control's evidence did not
                # complete for this scan - its absence from findings cannot
                # be read as a pass. Excluded from the denominator like
                # not_applicable/organizational, but for a different reason:
                # this is missing *evidence*, not a control the mapping pack
                # itself says a scan can't establish.
                status = "NOT_EVALUATED"
                excluded_count += 1
            else:
                # A completed scan that produced no finding for this rule, and
                # whose engine did not record the rule as failed to run, is
                # the absence-of-findings PASS this method reports on.
                status = EvaluationStatus.FAIL if failure else EvaluationStatus.PASS
            results.append(
                {
                    "rule_id": rule_id,
                    "control_id": control["control_id"],
                    "control_name": control["control_name"],
                    "status": status,
                    "severity": failure["severity"] if failure else None,
                    "category": failure["category"] if failure else None,
                    "resources": failure["resources"] if failure else 0,
                    "mapping_type": mapping_type,
                    "evidence_type": control.get("evidence_type"),
                    "primary_source": control.get("primary_source"),
                    "rationale": control.get("rationale"),
                    "owner": control.get("owner"),
                    "review_status": control.get("review_status"),
                    "review_date": control.get("review_date"),
                }
            )

        total = len(results)
        counts = {
            "passed": sum(1 for r in results if r["status"] == EvaluationStatus.PASS),
            "failed": sum(1 for r in results if r["status"] == EvaluationStatus.FAIL),
            "unknown": sum(1 for r in results if r["status"] == EvaluationStatus.UNKNOWN),
            "error": sum(1 for r in results if r["status"] == EvaluationStatus.ERROR),
            "not_applicable": sum(
                1 for r in results if r["status"] in (EvaluationStatus.NOT_APPLICABLE, "ORGANIZATIONAL")
            ),
            "not_evaluated": sum(1 for r in results if r["status"] == "NOT_EVALUATED"),
        }
        # UNKNOWN/ERROR must never improve the score: they count against the
        # denominator (evaluated coverage) without counting as a pass.
        # A scan exists and every control resolved, but every one of them is
        # excluded (not_applicable/organizational) - this is a different fact
        # from "no evidence exists at all" (NO_SCAN_DATA above), and callers
        # must not conflate the two the way a bare `in_scope_controls: 0`
        # would: a null score_percent alone can't say whether it's "nothing
        # was in scope" or "not evaluated yet".
        evaluated = total - counts["not_applicable"] - counts["not_evaluated"]
        score_pct = round((counts["passed"] / evaluated) * 100) if evaluated else None
        status = "OK" if evaluated else "NO_IN_SCOPE_CONTROLS"

        return {
            **pack_meta,
            "scan_id": scan_id,
            "contract_version": "2",
            "status": status,
            "mapping_provenance": mapping_provenance,
            "evaluation_basis": (
                "PASS reflects the absence of findings for this rule in the most recent "
                "completed scan, and the rule is excluded as NOT_EVALUATED rather than PASS "
                "when the scan engine recorded that it did not complete (raised an exception "
                "or returned malformed data) for this specific scan. It does not yet confirm "
                "the rule executed successfully against every applicable resource within a "
                "scan it did complete — a timed-out or permission-denied result on a subset "
                "of resources cannot currently be distinguished from a clean pass on all of "
                "them (full per-resource evaluation persistence is tracked in issue #263). "
                "Controls with mapping_type not_applicable or organizational are excluded "
                "from score_percent because a technical scan alone cannot establish them."
            ),
            "total_controls": total,
            "in_scope_controls": evaluated,
            "excluded_controls": counts["not_applicable"] + counts["not_evaluated"],
            "evaluated": evaluated,
            **counts,
            "score_percent": score_pct,
            "controls": results,
        }
