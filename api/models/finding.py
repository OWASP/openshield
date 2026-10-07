"""Finding dataclass and PostgreSQL-backed DatabaseManager."""

import hashlib
import json
import logging
import os
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras
import psycopg2.pool
from psycopg2 import extensions

from openshield.severity import (
    CONTRACT_VERSION,
    normalize_severity,
    score_counts,
    score_findings,
    severity_rank,
)
from scanner.evaluation import EvaluationStatus, aggregate_status

logger = logging.getLogger(__name__)

# Worker identities are per-process UUIDs. Heartbeat rows older than this are
# long-dead workers that no metric reads, so they are pruned to keep
# worker_heartbeats bounded. Must stay far above any heartbeat interval.
DEFAULT_WORKER_HEARTBEAT_RETENTION_SECONDS = 7 * 24 * 60 * 60


class LostLease(RuntimeError):
    """Raised when a worker no longer owns the scan it is trying to update."""


class ScanQuotaExceeded(RuntimeError):
    """Raised when an explicitly configured subscription scan quota is exhausted."""


FRAMEWORKS_DIR = Path(__file__).parent.parent.parent / "compliance" / "frameworks"

# One pool per DSN, shared across all DatabaseManager instances in this
# process. Routes create a new DatabaseManager per request, but they all
# borrow from the same small set of long-lived connections instead of
# opening a fresh PostgreSQL connection on every request.
_POOLS: Dict[str, "psycopg2.pool.ThreadedConnectionPool"] = {}
_POOLS_LOCK = threading.Lock()


_POOL_MAX_CONN = int(os.environ.get("DB_POOL_MAX_CONN", "10"))


def stable_finding_key(scan_id: str, finding: Dict[str, Any]) -> str:
    """Return an immutable identity for one logical finding in a scan.

    Rules that can report more than one violation for the same resource must
    provide ``finding_discriminator``.  Presentation fields such as severity,
    description, and remediation are deliberately excluded so retries update
    the existing authoritative finding rather than creating a duplicate.
    """
    resource_scope = finding.get("resource_id") or {
        "resource_type": finding.get("resource_type") or "",
        "resource_name": finding.get("resource_name") or "",
    }
    identity = {
        "scan_id": str(scan_id),
        "rule_id": finding.get("rule_id") or "",
        "resource_scope": resource_scope,
        "discriminator": finding.get("finding_discriminator") or "default",
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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
        if self.conn is not None:
            previous_conn = self.conn
            self.rollback(previous_conn)
            # rollback() discards a dead connection and clears self.conn. A
            # healthy connection still needs exactly one pool return before a
            # replacement is borrowed.
            if self.conn is previous_conn:
                self._return_connection(close=bool(previous_conn.closed), conn=previous_conn)
        self.conn = _get_pool(self.dsn).getconn()
        self.conn.autocommit = False
        logger.debug("Database connection acquired from pool")

    def _get_conn(self) -> Any:
        if self.conn is not None and self.conn.closed:
            self._return_connection(close=True)
        if self.conn is None:
            self.connect()
        return self.conn

    def _return_connection(self, close: bool = False, conn: Optional[Any] = None) -> None:
        """Return the checked-out connection, discarding it when requested."""
        conn = conn or self.conn
        if conn is None:
            return
        try:
            _get_pool(self.dsn).putconn(conn, close=close or bool(conn.closed))
            logger.debug("Database connection returned to pool")
        except Exception as exc:
            logger.error("Error returning connection to pool: %s", exc)
            try:
                conn.close()
            except Exception:
                pass
        finally:
            if self.conn is conn:
                self.conn = None

    def rollback(self, conn: Optional[Any] = None) -> None:
        """End a failed transaction, discarding a connection the server lost."""
        conn = conn or self.conn
        if conn is None:
            return
        try:
            if conn.closed or conn.info.transaction_status == extensions.TRANSACTION_STATUS_UNKNOWN:
                self._return_connection(close=True, conn=conn)
                return
            conn.rollback()
        except Exception as exc:
            logger.warning("Database rollback failed; discarding connection: %s", exc)
            self._return_connection(close=True, conn=conn)

    def close(self) -> None:
        """Return the connection to its pool (or discard it if broken)."""
        if self.conn is None:
            return
        try:
            self.rollback()
        finally:
            self._return_connection()

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

    def save_scan(self, scan_result: Dict[str, Any], lease_owner: str, fencing_token: int) -> None:
        """Persist a completed scan only while its worker still owns the lease.

        The ownership check and all authoritative result writes share one
        transaction.  A worker whose lease was reclaimed therefore cannot
        delete or insert child findings after it has become stale.
        """
        from datetime import datetime, timezone

        # Validate and canonicalize the entire batch before issuing SQL. A bad
        # severity must never be stored with a zero/default weight.
        findings = []
        for raw_finding in scan_result.get("findings", []):
            finding = dict(raw_finding)
            finding["severity"] = normalize_severity(finding.get("severity"))
            finding["finding_key"] = stable_finding_key(scan_result["scan_id"], finding)
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
        # Always written, even when empty: "this attempt had no failed rules"
        # is a real per-attempt result, not missing data. Omitting the key on a
        # clean retry would make the ON CONFLICT merge below extract SQL NULL
        # and stamp a JSON null over the previous attempt's outcomes.
        failed_rule_ids = scan_result.get("failed_rule_ids") or []
        mapping_snapshot_dict["_scan_rule_outcomes"] = {"failed_rule_ids": sorted(set(failed_rule_ids))}
        mapping_snapshot = json.dumps(mapping_snapshot_dict)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT scan_id
                    FROM scans
                    WHERE scan_id = %s
                      AND status = 'running'
                      AND lease_owner = %s
                      AND fencing_token = %s
                      AND lease_expires_at > CURRENT_TIMESTAMP
                    FOR UPDATE
                    """,
                    (scan_result["scan_id"], lease_owner, fencing_token),
                )
                if cur.fetchone() is None:
                    raise LostLease(f"Scan {scan_result['scan_id']} is no longer owned by this worker")
                cur.execute(
                    """
                    UPDATE scans
                    SET completed_at = %s,
                        total_findings = %s,
                        score = %s,
                        cve_enrichment_status = %s,
                        status = 'completed',
                        error_message = NULL,
                        severity_contract_version = %s,
                        lease_owner = NULL,
                        lease_expires_at = NULL,
                        -- The mapping-pack provenance captured by a scan_id's
                        -- first completed write is its historical record and
                        -- stays immutable on replay (a redelivered result for
                        -- the same scan_id), so it is only filled in when
                        -- absent. _scan_rule_outcomes is per-attempt execution
                        -- state, not provenance: it always reflects the
                        -- findings written by *this* save, so it is re-merged
                        -- on every write instead of being frozen with the rest
                        -- of the snapshot. The inner COALESCE keeps that
                        -- re-merge from ever writing a JSON null: save_scan()
                        -- always supplies the key (empty list included), but a
                        -- row written by any other path without it falls back
                        -- to the stored outcomes rather than being nulled out.
                        compliance_mapping_snapshot = COALESCE(
                            compliance_mapping_snapshot, %s::jsonb
                        ) || jsonb_build_object(
                            '_scan_rule_outcomes',
                            COALESCE(
                                %s::jsonb -> '_scan_rule_outcomes',
                                compliance_mapping_snapshot -> '_scan_rule_outcomes',
                                '{"failed_rule_ids": []}'::jsonb
                            )
                        )
                    WHERE scan_id = %s
                    """,
                    (
                        completed_at,
                        len(findings),
                        score_findings(findings),
                        scan_result.get("cve_enrichment_status", "PENDING"),
                        CONTRACT_VERSION,
                        mapping_snapshot,
                        mapping_snapshot,
                        scan_result["scan_id"],
                    ),
                )
                finding_id_by_key: Dict[Any, int] = {}
                for f in findings:
                    cur.execute(
                        """
                        INSERT INTO findings
                            (scan_id, finding_key, rule_id, rule_name, severity, category,
                             resource_id, resource_name, resource_type,
                             description, remediation, playbook,
                             frameworks, metadata, cve_references,
                             cvss_score, exploit_available, detected_at)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (scan_id, finding_key) DO UPDATE SET
                            rule_name = EXCLUDED.rule_name,
                            severity = EXCLUDED.severity,
                            category = EXCLUDED.category,
                            resource_name = EXCLUDED.resource_name,
                            resource_type = EXCLUDED.resource_type,
                            description = EXCLUDED.description,
                            remediation = EXCLUDED.remediation,
                            playbook = EXCLUDED.playbook,
                            frameworks = EXCLUDED.frameworks,
                            metadata = EXCLUDED.metadata,
                            cve_references = EXCLUDED.cve_references,
                            cvss_score = EXCLUDED.cvss_score,
                            exploit_available = EXCLUDED.exploit_available,
                            detected_at = EXCLUDED.detected_at
                        RETURNING id
                        """,
                        (
                            # The parent scan owns every child in this batch.
                            # Never trust a caller-supplied child scan_id.
                            scan_result["scan_id"],
                            f["finding_key"],
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
                    # DO UPDATE still returns the row, so a replayed result
                    # keeps the *existing* finding id rather than minting a new
                    # one. Evaluation rows already pointing at it stay valid.
                    finding_row = cur.fetchone()
                    finding_id_by_key[(f.get("rule_id"), f.get("resource_id"))] = (
                        finding_row["id"] if isinstance(finding_row, dict) else finding_row[0]
                    )

                # Findings the current result no longer reports are removed by
                # identity rather than by wiping the whole child set, so a
                # replayed delivery never briefly empties a populated scan.
                finding_keys = [f["finding_key"] for f in findings]
                if finding_keys:
                    cur.execute(
                        "DELETE FROM findings WHERE scan_id = %s AND NOT (finding_key = ANY(%s))",
                        (scan_result["scan_id"], finding_keys),
                    )
                else:
                    cur.execute("DELETE FROM findings WHERE scan_id = %s", (scan_result["scan_id"],))

                # Coverage rows (#263): a status for every resource a migrated
                # rule looked at, not just its violations. The evaluation
                # contract itself belongs to #321 and is reproduced here
                # unchanged; what this change adds is that these writes now
                # happen inside the fenced transaction above, so a worker that
                # lost its lease cannot rewrite another owner's coverage.
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

                # Completion creates one durable job in this same fenced
                # transaction. The scan_id uniqueness constraint makes result
                # replay harmless and prevents duplicate enrichment delivery.
                cur.execute(
                    """
                    INSERT INTO enrichment_jobs (job_id, scan_id, status, attempt_count, checkpoint)
                    VALUES (%s, %s, 'pending', 0, 0)
                    ON CONFLICT (scan_id) DO NOTHING
                    """,
                    (str(uuid.uuid4()), scan_result["scan_id"]),
                )
            conn.commit()
        except Exception:
            # psycopg2 connections remain in an aborted transaction after any
            # SQL error. Roll back here so the worker can record failure and
            # safely process subsequent scans on the same pooled connection.
            self.rollback(conn)
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

    def enqueue_enrichment_job(self, scan_id: str) -> tuple[Dict[str, Any], str]:
        """Durably enqueue, or explicitly requeue, one CVE enrichment job.

        Returns the job row and one of four outcomes:

        ``created``    a new job row was inserted for this scan.
        ``requeued``   a terminally ``failed`` job was reset to ``pending``.
        ``active``     a ``pending``/``running`` job already exists.
        ``completed``  enrichment already finished; nothing was changed.

        There is never more than one job per scan: the ``scan_id`` unique
        constraint makes the insert idempotent, and the requeue is a single
        conditional ``UPDATE`` so concurrent callers converge on one row.  A
        ``running`` job is left strictly alone -- only its lease expiring
        (:meth:`recover_stale_enrichment_jobs`) may take it away from its
        current owner, so an operator retry can never steal a live claim.
        """
        conn = self._get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # A scan enriched before durable jobs existed has no job row
                # to report, but it must not be re-enriched either. Record the
                # work as already finished so every caller gets the same
                # {outcome, job_id} answer instead of a second contract.
                cur.execute(
                    """
                    INSERT INTO enrichment_jobs (job_id, scan_id, status, attempt_count, checkpoint, completed_at)
                    SELECT %s, %s,
                           CASE WHEN s.cve_enrichment_status = 'COMPLETED' THEN 'completed' ELSE 'pending' END,
                           0, 0,
                           CASE WHEN s.cve_enrichment_status = 'COMPLETED' THEN CURRENT_TIMESTAMP END
                    FROM scans s
                    WHERE s.scan_id = %s
                    ON CONFLICT (scan_id) DO NOTHING
                    RETURNING *
                    """,
                    (str(uuid.uuid4()), scan_id, scan_id),
                )
                job = cur.fetchone()
                if job is not None:
                    job = dict(job)
                    if job["status"] == "completed":
                        conn.commit()
                        return job, "completed"
                    cur.execute(
                        "UPDATE scans SET cve_enrichment_status = 'PENDING' WHERE scan_id = %s",
                        (scan_id,),
                    )
                    conn.commit()
                    return job, "created"

                # A job already exists. Only a terminally failed one is
                # revived, and the WHERE clause is the whole guard: a
                # concurrent requeue that lost the race sees status
                # 'pending' and matches nothing, so both callers end up
                # with the same single pending job.
                #
                # attempt_count restarts because the operator is explicitly
                # granting a fresh retry budget -- leaving it at the limit
                # would make the job fail again on its first attempt. The
                # previous error_message is kept as the audit trail, and
                # checkpoint is kept so the retry resumes rather than
                # re-enriching findings that already succeeded.
                cur.execute(
                    """
                    UPDATE enrichment_jobs
                    SET status = 'pending',
                        attempt_count = 0,
                        next_retry_at = CURRENT_TIMESTAMP,
                        lease_owner = NULL,
                        lease_expires_at = NULL,
                        last_heartbeat_at = NULL,
                        completed_at = NULL
                    WHERE scan_id = %s AND status = 'failed'
                    RETURNING *
                    """,
                    (scan_id,),
                )
                requeued = cur.fetchone()
                if requeued is not None:
                    cur.execute(
                        "UPDATE scans SET cve_enrichment_status = 'PENDING' WHERE scan_id = %s",
                        (scan_id,),
                    )
                    conn.commit()
                    return dict(requeued), "requeued"

                cur.execute("SELECT * FROM enrichment_jobs WHERE scan_id = %s", (scan_id,))
                existing = cur.fetchone()
                if existing is None:
                    raise RuntimeError("enrichment job conflict did not return an existing job")
            conn.commit()
            existing = dict(existing)
            return existing, "completed" if existing["status"] == "completed" else "active"
        except Exception:
            self.rollback(conn)
            raise

    def claim_next_enrichment_job(
        self, lease_owner: str, lease_seconds: int, scan_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Atomically claim the next retry-ready enrichment job.

        ``scan_id`` restricts the claim to one scan's job, with the same lease
        and fencing semantics as an unrestricted claim.
        """
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        conn = self._get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    UPDATE enrichment_jobs
                    SET status = 'running', lease_owner = %s,
                        lease_expires_at = CURRENT_TIMESTAMP + (%s * INTERVAL '1 second'),
                        last_heartbeat_at = CURRENT_TIMESTAMP,
                        fencing_token = fencing_token + 1,
                        attempt_count = attempt_count + 1,
                        error_message = NULL
                    WHERE job_id = (
                        SELECT job_id FROM enrichment_jobs
                        WHERE status = 'pending'
                          AND next_retry_at <= CURRENT_TIMESTAMP
                          AND (%s IS NULL OR scan_id = %s::uuid)
                        ORDER BY created_at ASC
                        FOR UPDATE SKIP LOCKED
                        LIMIT 1
                    )
                    RETURNING *
                    """,
                    (lease_owner, lease_seconds, scan_id, scan_id),
                )
                job = cur.fetchone()
                if job:
                    cur.execute(
                        "UPDATE scans SET cve_enrichment_status = 'ENRICHING' WHERE scan_id = %s", (job["scan_id"],)
                    )
            conn.commit()
            return dict(job) if job else None
        except Exception:
            self.rollback(conn)
            raise

    def heartbeat_enrichment_job(self, job_id: str, lease_owner: str, fencing_token: int, lease_seconds: int) -> None:
        """Renew an enrichment claim or raise LostLease."""
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE enrichment_jobs
                    SET lease_expires_at = CURRENT_TIMESTAMP + (%s * INTERVAL '1 second'),
                        last_heartbeat_at = CURRENT_TIMESTAMP
                    WHERE job_id = %s AND status = 'running'
                      AND lease_owner = %s AND fencing_token = %s
                      AND lease_expires_at > CURRENT_TIMESTAMP
                    """,
                    (lease_seconds, job_id, lease_owner, fencing_token),
                )
                if cur.rowcount != 1:
                    raise LostLease(f"Enrichment job {job_id} is no longer owned by this worker")
            conn.commit()
        except Exception:
            self.rollback(conn)
            raise

    def get_enrichment_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        """Return a deterministic snapshot ordered for checkpointed enrichment."""
        conn = self._get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM findings WHERE scan_id = %s ORDER BY id ASC", (scan_id,))
            return [dict(row) for row in cur.fetchall()]

    def persist_enrichment_progress(
        self,
        job_id: str,
        lease_owner: str,
        fencing_token: int,
        finding: Dict[str, Any],
        checkpoint: int,
    ) -> None:
        """Persist one finding and checkpoint it under the current job fence."""
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT scan_id FROM enrichment_jobs
                    WHERE job_id = %s AND status = 'running'
                      AND lease_owner = %s AND fencing_token = %s
                      AND lease_expires_at > CURRENT_TIMESTAMP
                    FOR UPDATE
                    """,
                    (job_id, lease_owner, fencing_token),
                )
                if cur.fetchone() is None:
                    raise LostLease(f"Enrichment job {job_id} lost its lease before checkpointing")
                cur.execute(
                    """
                    UPDATE findings SET cve_references = %s, cvss_score = %s, exploit_available = %s
                    WHERE id = %s
                    """,
                    (
                        json.dumps(finding.get("cve_references", [])),
                        finding.get("cvss_score"),
                        finding.get("exploit_available", False),
                        finding["id"],
                    ),
                )
                cur.execute("UPDATE enrichment_jobs SET checkpoint = %s WHERE job_id = %s", (checkpoint, job_id))
            conn.commit()
        except Exception:
            self.rollback(conn)
            raise

    def complete_enrichment_job(self, job_id: str, lease_owner: str, fencing_token: int) -> None:
        """Atomically complete a fenced job and its scan's enrichment state."""
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE enrichment_jobs
                    SET status = 'completed', completed_at = CURRENT_TIMESTAMP,
                        lease_owner = NULL, lease_expires_at = NULL
                    WHERE job_id = %s AND status = 'running'
                      AND lease_owner = %s AND fencing_token = %s
                      AND lease_expires_at > CURRENT_TIMESTAMP
                    RETURNING scan_id
                    """,
                    (job_id, lease_owner, fencing_token),
                )
                row = cur.fetchone()
                if row is None:
                    raise LostLease(f"Enrichment job {job_id} lost its lease before completion")
                scan_id = row[0]
                cur.execute("UPDATE scans SET cve_enrichment_status = 'COMPLETED' WHERE scan_id = %s", (scan_id,))
            conn.commit()
        except Exception:
            self.rollback(conn)
            raise

    def fail_enrichment_job(
        self,
        job_id: str,
        lease_owner: str,
        fencing_token: int,
        error_message: str,
        *,
        max_attempts: int = 3,
        retry_seconds: int = 30,
    ) -> str:
        """Record bounded retry state under the job's current fencing token."""
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT scan_id, attempt_count FROM enrichment_jobs
                    WHERE job_id = %s AND status = 'running'
                      AND lease_owner = %s AND fencing_token = %s
                      AND lease_expires_at > CURRENT_TIMESTAMP
                    FOR UPDATE
                    """,
                    (job_id, lease_owner, fencing_token),
                )
                row = cur.fetchone()
                if row is None:
                    raise LostLease(f"Enrichment job {job_id} is no longer owned by this worker")
                scan_id, attempt_count = row
                terminal = attempt_count >= max_attempts
                if terminal:
                    cur.execute(
                        """
                        UPDATE enrichment_jobs SET status = 'failed', completed_at = CURRENT_TIMESTAMP,
                            error_message = %s, lease_owner = NULL, lease_expires_at = NULL
                        WHERE job_id = %s
                        """,
                        (error_message, job_id),
                    )
                    scan_status = "FAILED"
                    outcome = "failed"
                else:
                    cur.execute(
                        """
                        UPDATE enrichment_jobs SET status = 'pending', error_message = %s,
                            lease_owner = NULL, lease_expires_at = NULL,
                            next_retry_at = CURRENT_TIMESTAMP + (%s * INTERVAL '1 second')
                        WHERE job_id = %s
                        """,
                        (error_message, retry_seconds, job_id),
                    )
                    scan_status = "PENDING"
                    outcome = "retry"
                cur.execute("UPDATE scans SET cve_enrichment_status = %s WHERE scan_id = %s", (scan_status, scan_id))
            conn.commit()
            return outcome
        except Exception:
            self.rollback(conn)
            raise

    def recover_stale_enrichment_jobs(self, max_attempts: int = 3) -> int:
        """Recover expired enrichment claims without blocking the worker loop.

        Selection, job transition, and parent-scan status update are one
        statement.  Both rows are locked with ``SKIP LOCKED`` so a job (or its
        scan) currently handled by another transaction is deferred to a later
        recovery pass instead of convoying all queue work behind it.
        """
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    WITH stale AS (
                        SELECT j.job_id, j.scan_id, j.attempt_count
                        FROM enrichment_jobs AS j
                        JOIN scans AS s ON s.scan_id = j.scan_id
                        WHERE j.status = 'running'
                          AND j.lease_expires_at < CURRENT_TIMESTAMP
                        ORDER BY j.lease_expires_at ASC, j.job_id ASC
                        FOR UPDATE OF j, s SKIP LOCKED
                    ), transitioned AS (
                        UPDATE enrichment_jobs AS j
                        SET status = CASE
                                WHEN stale.attempt_count >= %(max_attempts)s THEN 'failed'
                                ELSE 'pending'
                            END,
                            completed_at = CASE
                                WHEN stale.attempt_count >= %(max_attempts)s THEN CURRENT_TIMESTAMP
                                ELSE j.completed_at
                            END,
                            lease_owner = NULL,
                            lease_expires_at = NULL,
                            error_message = CASE
                                WHEN stale.attempt_count >= %(max_attempts)s
                                THEN 'Enrichment exceeded maximum retry attempts after worker interruption.'
                                ELSE 'Enrichment worker interrupted; queued for retry.'
                            END
                        FROM stale
                        WHERE j.job_id = stale.job_id
                        RETURNING j.job_id, j.scan_id, j.status
                    ), updated_scans AS (
                        UPDATE scans AS s
                        SET cve_enrichment_status = CASE
                                WHEN transitioned.status = 'failed' THEN 'FAILED'
                                ELSE 'PENDING'
                            END
                        FROM transitioned
                        WHERE s.scan_id = transitioned.scan_id
                        RETURNING transitioned.job_id, transitioned.scan_id, transitioned.status
                    )
                    SELECT job_id, scan_id, status FROM updated_scans
                    """,
                    {"max_attempts": max_attempts},
                )
                transitions = cur.fetchall()
            conn.commit()
            return len(transitions)
        except Exception:
            self.rollback(conn)
            raise

    def admit_scan(
        self,
        scan_id: str,
        subscription_id: str,
        *,
        idempotency_key: Optional[str] = None,
        max_scans_per_hour: int = 0,
    ) -> tuple[Dict[str, Any], bool]:
        """Atomically admit one scan or return its durable logical predecessor.

        The PostgreSQL advisory transaction lock serializes admission decisions
        for one subscription.  The partial unique index added by the migration
        remains the final database enforcement of the one-active-scan rule.
        """
        if max_scans_per_hour < 0:
            raise ValueError("max_scans_per_hour must not be negative")
        conn = self._get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (subscription_id,))
                if idempotency_key:
                    cur.execute(
                        """
                        SELECT * FROM scans
                        WHERE subscription_id = %s AND idempotency_key = %s
                        """,
                        (subscription_id, idempotency_key),
                    )
                    existing = cur.fetchone()
                    if existing:
                        # The key is scoped to this subscription and a trigger
                        # carries no other semantic input, so a hit here is
                        # always a replay of the same logical request.
                        conn.commit()
                        return dict(existing), False

                cur.execute(
                    """
                    SELECT * FROM scans
                    WHERE subscription_id = %s AND status IN ('pending', 'running')
                    ORDER BY started_at ASC
                    LIMIT 1
                    """,
                    (subscription_id,),
                )
                active_scan = cur.fetchone()
                if active_scan:
                    conn.commit()
                    return dict(active_scan), False

                if max_scans_per_hour:
                    cur.execute(
                        """
                        SELECT COUNT(*) FROM scans
                        WHERE subscription_id = %s
                          AND started_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour'
                        """,
                        (subscription_id,),
                    )
                    quota_row = cur.fetchone()
                    scan_count = quota_row["count"] if isinstance(quota_row, dict) else quota_row[0]
                    if scan_count >= max_scans_per_hour:
                        raise ScanQuotaExceeded("Configured hourly scan quota has been reached")

                from datetime import datetime, timezone

                cur.execute(
                    """
                    INSERT INTO scans (
                        scan_id, subscription_id, started_at, status, attempt_count,
                        idempotency_key
                    )
                    VALUES (%s, %s, %s, 'pending', 0, %s)
                    RETURNING *
                    """,
                    (
                        scan_id,
                        subscription_id,
                        datetime.now(timezone.utc).isoformat(),
                        idempotency_key,
                    ),
                )
                admitted = dict(cur.fetchone())
            conn.commit()
            logger.info("Admitted pending scan %s for %s", scan_id, subscription_id)
            return admitted, True
        except Exception:
            self.rollback(conn)
            raise

    def create_pending_scan(self, scan_id: str, subscription_id: str) -> None:
        """Create a pending scan for older internal callers without a key."""
        self.admit_scan(scan_id, subscription_id)

    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        error_message: Optional[str],
        *,
        lease_owner: str,
        fencing_token: int,
    ) -> None:
        """Record a terminal failure while the caller still owns the lease."""
        if status != "failed":
            raise ValueError("Fenced status updates only support terminal failures")
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scans
                    SET status = 'failed',
                        error_message = %s,
                        lease_owner = NULL,
                        lease_expires_at = NULL
                    WHERE scan_id = %s
                      AND status = 'running'
                      AND lease_owner = %s
                      AND fencing_token = %s
                      AND lease_expires_at > CURRENT_TIMESTAMP
                    """,
                    (error_message, scan_id, lease_owner, fencing_token),
                )
                if cur.rowcount != 1:
                    raise LostLease(f"Scan {scan_id} is no longer owned by this worker")
            conn.commit()
        except Exception:
            self.rollback(conn)
            raise
        logger.info("Updated scan %s status to %s", scan_id, status)

    def claim_next_pending_scan(
        self, lease_owner: str, lease_seconds: int, scan_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Atomically claim one pending scan and establish its renewable lease.

        ``scan_id`` restricts the claim to one specific scan instead of the
        oldest pending one.  The lease, fencing and skip-locked semantics are
        identical either way; callers that must act on a known scan use it so
        they neither depend on nor disturb the shared queue order.
        """
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        conn = self._get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    UPDATE scans
                    SET status = 'running',
                        claimed_at = CURRENT_TIMESTAMP,
                        lease_owner = %s,
                        lease_expires_at = CURRENT_TIMESTAMP + (%s * INTERVAL '1 second'),
                        last_heartbeat_at = CURRENT_TIMESTAMP,
                        fencing_token = COALESCE(fencing_token, 0) + 1,
                        attempt_count = COALESCE(attempt_count, 0) + 1,
                        error_message = NULL
                    WHERE scan_id = (
                        SELECT scan_id
                        FROM scans
                        WHERE status = 'pending'
                          AND (%s IS NULL OR scan_id = %s::uuid)
                        ORDER BY started_at ASC
                        FOR UPDATE SKIP LOCKED
                        LIMIT 1
                    )
                    RETURNING *
                    """,
                    (lease_owner, lease_seconds, scan_id, scan_id),
                )
                row = cur.fetchone()
            conn.commit()
            return dict(row) if row else None
        except Exception:
            self.rollback(conn)
            raise

    def heartbeat_scan(self, scan_id: str, lease_owner: str, fencing_token: int, lease_seconds: int) -> Dict[str, Any]:
        """Renew a still-valid lease, or raise :class:`LostLease`."""
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        conn = self._get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    UPDATE scans
                    SET lease_expires_at = CURRENT_TIMESTAMP + (%s * INTERVAL '1 second'),
                        last_heartbeat_at = CURRENT_TIMESTAMP
                    WHERE scan_id = %s
                      AND status = 'running'
                      AND lease_owner = %s
                      AND fencing_token = %s
                      AND lease_expires_at > CURRENT_TIMESTAMP
                    RETURNING *
                    """,
                    (lease_seconds, scan_id, lease_owner, fencing_token),
                )
                row = cur.fetchone()
            if row is None:
                self.rollback(conn)
                raise LostLease(f"Scan {scan_id} lease was lost before heartbeat")
            conn.commit()
            return dict(row)
        except LostLease:
            raise
        except Exception:
            self.rollback(conn)
            raise

    def recover_stale_scans(self, max_attempts: int = 3) -> int:
        """Recover scans only after their renewable leases have expired.

        ``attempt_count`` counts claims that have already been *started*:
        :meth:`claim_next_pending_scan` increments it as part of the same
        statement that takes the lease, so a scan being executed for the
        first time already reads 1.  A stale scan is therefore returned to
        ``pending`` while ``attempt_count < max_attempts`` and is failed once
        it reaches that limit, giving every scan exactly ``max_attempts``
        executions.  Rows predating the column read NULL and are treated as
        zero attempts so they get the full budget rather than being retired a
        run early.

        Selection and transition are one statement.  The CTE takes
        ``FOR UPDATE SKIP LOCKED`` so a row another worker is already
        recovering (or executing) is stepped over instead of waited on: this
        runs at the top of every worker iteration, so blocking here would
        stall claiming and enrichment behind one stuck row.
        """
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    WITH stale AS (
                        SELECT scan_id, COALESCE(attempt_count, 0) AS attempts
                        FROM scans
                        WHERE status = 'running'
                          AND lease_expires_at < CURRENT_TIMESTAMP
                        ORDER BY lease_expires_at ASC
                        FOR UPDATE SKIP LOCKED
                    )
                    UPDATE scans AS s
                    SET status = CASE WHEN stale.attempts >= %(max_attempts)s THEN 'failed' ELSE 'pending' END,
                        claimed_at = CASE WHEN stale.attempts >= %(max_attempts)s THEN s.claimed_at END,
                        last_heartbeat_at = CASE
                            WHEN stale.attempts >= %(max_attempts)s THEN s.last_heartbeat_at
                        END,
                        lease_owner = NULL,
                        lease_expires_at = NULL,
                        error_message = CASE
                            WHEN stale.attempts >= %(max_attempts)s
                            THEN 'Scan exceeded maximum retry attempts after worker interruption.'
                            ELSE 'Scan worker interrupted before completion. Queued for retry.'
                        END
                    FROM stale
                    WHERE s.scan_id = stale.scan_id
                    RETURNING s.status
                    """,
                    {"max_attempts": max_attempts},
                )
                statuses = [row[0] for row in cur.fetchall()]
            conn.commit()
        except Exception:
            self.rollback(conn)
            raise
        failed_count = statuses.count("failed")
        retry_count = statuses.count("pending")
        total_count = len(statuses)
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

    def record_worker_heartbeat(
        self,
        worker_id: str,
        worker_type: str,
        retention_seconds: int = DEFAULT_WORKER_HEARTBEAT_RETENTION_SECONDS,
    ) -> None:
        """Persist liveness without using worker IDs as metric labels.

        Worker identities are per-process, so a long-lived deployment would
        otherwise accumulate one dead row per restart forever.  Retired rows
        are pruned only on the heartbeat that actually inserts a new worker
        identity -- i.e. once per worker process -- so the table stays bounded
        without a scheduler and without a full-table sweep on every beat.
        """
        if worker_type not in {"scan", "enrichment"}:
            raise ValueError("unsupported worker type")
        if retention_seconds <= 0:
            raise ValueError("retention_seconds must be positive")
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO worker_heartbeats (worker_id, worker_type, last_seen_at)
                    VALUES (%s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT (worker_id, worker_type) DO UPDATE SET
                        last_seen_at = EXCLUDED.last_seen_at
                    RETURNING (xmax = 0) AS inserted
                    """,
                    (worker_id, worker_type),
                )
                row = cur.fetchone()
                inserted = row["inserted"] if isinstance(row, dict) else row[0]
                if inserted:
                    # Retention is far longer than any heartbeat interval, so a
                    # live worker can never prune itself or a peer.
                    cur.execute(
                        """
                        DELETE FROM worker_heartbeats
                        WHERE last_seen_at < CURRENT_TIMESTAMP - (%s * INTERVAL '1 second')
                        """,
                        (retention_seconds,),
                    )
            conn.commit()
        except Exception:
            self.rollback(conn)
            raise

    def get_operational_metrics(self) -> Dict[str, Any]:
        """Return bounded aggregates used by the public Prometheus endpoint."""
        conn = self._get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT COALESCE(EXTRACT(EPOCH FROM CURRENT_TIMESTAMP - MIN(started_at)), 0) AS value
                    FROM scans WHERE status = 'pending'
                    """
                )
                scan_queue_age = cur.fetchone()["value"]
                cur.execute(
                    """
                    SELECT COALESCE(EXTRACT(EPOCH FROM CURRENT_TIMESTAMP - MIN(created_at)), 0) AS value
                    FROM enrichment_jobs WHERE status = 'pending'
                    """
                )
                enrichment_queue_age = cur.fetchone()["value"]
                # Lease age is the freshness of the *current* lease, not how
                # long ago the scan was first claimed. Measuring claimed_at
                # made this climb for the whole life of a healthy long scan
                # even while its worker was heartbeating on schedule, so the
                # metric could not distinguish "slow but alive" from "stalled".
                # last_heartbeat_at is what the lease actually renews, and is
                # what the enrichment counterpart below already reports.
                # Rows migrated into leases predate any heartbeat, so they fall
                # back to their claim time rather than dropping out of MIN().
                cur.execute(
                    """
                    SELECT COALESCE(
                        EXTRACT(EPOCH FROM CURRENT_TIMESTAMP - MIN(COALESCE(last_heartbeat_at, claimed_at))), 0
                    ) AS value
                    FROM scans WHERE status = 'running'
                    """
                )
                scan_lease_age = cur.fetchone()["value"]
                cur.execute(
                    """
                    SELECT COALESCE(EXTRACT(EPOCH FROM CURRENT_TIMESTAMP - MIN(last_heartbeat_at)), 0) AS value
                    FROM enrichment_jobs WHERE status = 'running'
                    """
                )
                enrichment_lease_age = cur.fetchone()["value"]
                cur.execute("SELECT COALESCE(SUM(GREATEST(attempt_count - 1, 0)), 0) AS value FROM scans")
                scan_retries = cur.fetchone()["value"]
                cur.execute("SELECT COALESCE(SUM(GREATEST(attempt_count - 1, 0)), 0) AS value FROM enrichment_jobs")
                enrichment_retries = cur.fetchone()["value"]
                cur.execute(
                    """
                    SELECT worker_type, EXTRACT(EPOCH FROM CURRENT_TIMESTAMP - MAX(last_seen_at)) AS age
                    FROM worker_heartbeats GROUP BY worker_type
                    """
                )
                heartbeat_age = {row["worker_type"]: float(row["age"]) for row in cur.fetchall()}
                cur.execute(
                    """
                    SELECT COALESCE(EXTRACT(EPOCH FROM MAX(completed_at)), 0) AS value
                    FROM scans WHERE status = 'completed'
                    """
                )
                last_success = cur.fetchone()["value"]
            conn.commit()
            return {
                "oldest_queue_age": {"scan": float(scan_queue_age), "enrichment": float(enrichment_queue_age)},
                "oldest_lease_age": {"scan": float(scan_lease_age), "enrichment": float(enrichment_lease_age)},
                "retry_attempts": {"scan": float(scan_retries), "enrichment": float(enrichment_retries)},
                "worker_heartbeat_age": heartbeat_age,
                "last_successful_scan_timestamp": float(last_success),
            }
        except Exception:
            self.rollback(conn)
            raise

    # ------------------------------------------------------------------ #
    # Scoring                                                               #
    # ------------------------------------------------------------------ #

    def get_score(self, subscription_id: Optional[str] = None) -> Dict[str, Any]:
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

        Args:
            subscription_id: When given, scopes the "latest completed scan"
                lookup to this subscription. In a shared-database deployment
                that stores scans for more than one Azure subscription,
                omitting this returns whichever subscription scanned most
                recently - not this caller's own data. Passed in by the route
                (matching get_compliance_score) rather than read off the
                instance, which never carries it.

        Returns:
            {"status": "NO_SCAN_DATA", "score": None, "message": ...} when no
            completed scan exists yet, or {"status": "OK", "score": <0-100>}
            once one has.
        """
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
        mapping is not independently reviewed, or whose mapping_type is
        "not_applicable" or "organizational", are listed but excluded from
        the pass-rate denominator (score_percent). An unreviewed mapping must
        not be presented as direct evidence, even when its mapping_type says
        "direct".

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
            excluded_controls, reviewed_controls, unreviewed_controls,
            passed, failed, score_percent, controls (list
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
                    "reviewed_controls": None,
                    "unreviewed_controls": None,
                    "not_applicable": None,
                    "organizational": None,
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

            # Pass/fail/unknown/error status is evaluation-derived (#263/#321):
            # it comes from rule_evaluations, never from the mere absence of a
            # finding. A rule that was never run against this scan (a legacy
            # rule not yet migrated to evaluate(), or one that was skipped)
            # has no row here and is reported UNKNOWN below, not a silent PASS.
            cur2.execute(
                """
                SELECT rule_id, status
                FROM rule_evaluations
                WHERE scan_id = %s
                """,
                (scan_id,),
            )
            evaluation_rows = cur2.fetchall()

        statuses_by_rule: Dict[str, List[str]] = {}
        for rule_id, status in evaluation_rows:
            statuses_by_rule.setdefault(rule_id, []).append(status)
        # FAIL beats ERROR beats UNKNOWN beats PASS beats NOT_APPLICABLE, so a
        # single failing/erroring resource can never be outvoted by resources
        # that happened to pass under the same rule.
        aggregated_status = {rid: aggregate_status(sts) for rid, sts in statuses_by_rule.items()}

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

        # Rules the scan engine could not complete for this scan (raised, or
        # returned malformed data) - recorded by save_scan() alongside the
        # mapping snapshot. This is a supplementary signal on top of
        # rule_evaluations: it can only ever make a control's status stricter
        # (force ERROR), never looser, and an ERROR still counts in the
        # denominator, so a rule that failed to run can never improve a score
        # (issue #302/#263).
        unevaluated_rule_ids = set((snapshot.get("_scan_rule_outcomes") or {}).get("failed_rule_ids") or [])

        results = []
        for rule_id, control in controls.items():
            mapping_type = control.get("mapping_type", "supporting")
            review_status = control.get("review_status")
            failure = failures.get(rule_id)
            # Review status is an evidence gate, not just display metadata.
            # A control-by-control review is required before a mapping can
            # yield PASS/FAIL evidence or enter the score denominator. Treat
            # absent/unknown review_status conservatively as unreviewed so
            # legacy mapping snapshots cannot acquire evidence weight merely
            # because they predate this field.
            if review_status != "reviewed":
                status = "UNREVIEWED_MAPPING"
            elif mapping_type == "not_applicable":
                status = EvaluationStatus.NOT_APPLICABLE
            elif mapping_type == "organizational":
                status = "ORGANIZATIONAL"
            else:
                # Evaluation-derived (#263/#321). A control's status is the
                # rolled-up status of its rule's rule_evaluations rows for
                # this scan. No rows at all -> UNKNOWN: the rule was never
                # actually run against this scan (a legacy rule not migrated
                # to evaluate(), or one that was skipped), and the absence of
                # a finding must never be promoted to a PASS on its own.
                status = aggregated_status.get(rule_id, EvaluationStatus.UNKNOWN)
                if rule_id in unevaluated_rule_ids and status in (
                    EvaluationStatus.PASS,
                    EvaluationStatus.UNKNOWN,
                ):
                    # The engine explicitly recorded this rule as failing to
                    # complete for this scan; a PASS/UNKNOWN rolled up from
                    # partial evaluation rows must not mask that.
                    status = EvaluationStatus.ERROR
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
                    "review_status": review_status,
                    "review_date": control.get("review_date"),
                }
            )

        total = len(results)
        counts = {
            "passed": sum(1 for r in results if r["status"] == EvaluationStatus.PASS),
            "failed": sum(1 for r in results if r["status"] == EvaluationStatus.FAIL),
            "unknown": sum(1 for r in results if r["status"] == EvaluationStatus.UNKNOWN),
            "error": sum(1 for r in results if r["status"] == EvaluationStatus.ERROR),
            "not_applicable": sum(1 for r in results if r["status"] == EvaluationStatus.NOT_APPLICABLE),
            "organizational": sum(1 for r in results if r["status"] == "ORGANIZATIONAL"),
            "unreviewed_controls": sum(1 for r in results if r["status"] == "UNREVIEWED_MAPPING"),
        }
        counts["reviewed_controls"] = total - counts["unreviewed_controls"]
        # Unreviewed mappings join not_applicable and organizational controls
        # outside the denominator. UNKNOWN and ERROR for *reviewed* mappings
        # stay in it: lost evidence must lower a score, not shrink its base.
        # A completed scan with no reviewed controls is distinct from both no
        # scan data and a reviewed pack containing only excluded controls.
        excluded = counts["not_applicable"] + counts["organizational"] + counts["unreviewed_controls"]
        evaluated = total - excluded
        score_pct = round((counts["passed"] / evaluated) * 100) if evaluated else None
        if evaluated:
            status = "OK"
        elif counts["reviewed_controls"] == 0:
            status = "NO_REVIEWED_CONTROLS"
        else:
            status = "NO_IN_SCOPE_CONTROLS"

        return {
            **pack_meta,
            "scan_id": scan_id,
            "contract_version": "3",
            "status": status,
            "mapping_provenance": mapping_provenance,
            "evaluation_basis": (
                "Status is evaluation-derived: PASS/FAIL/UNKNOWN/ERROR for each control is "
                "the rolled-up status of its rule's persisted rule_evaluations rows for the "
                "most recent completed scan (issue #263). A rule with no evaluation row for "
                "this scan - a legacy rule not yet migrated to evaluate(), or one that was "
                "skipped - is reported UNKNOWN, never a PASS inferred from the mere absence "
                "of a finding; a rule the scan engine recorded as failing to complete is "
                "forced to ERROR. UNKNOWN and ERROR count in the score_percent denominator "
                "without counting as a pass, so missing or lost evidence lowers the score. "
                "Findings supply only the severity/category/affected-resource detail on "
                "failing controls. Controls with review_status other than reviewed are "
                "UNREVIEWED_MAPPING and excluded from score_percent; not_applicable and "
                "organizational controls are also excluded because a technical scan alone "
                "cannot establish them."
            ),
            "total_controls": total,
            "in_scope_controls": evaluated,
            "excluded_controls": excluded,
            "evaluated": evaluated,
            **counts,
            "score_percent": score_pct,
            "controls": results,
        }
