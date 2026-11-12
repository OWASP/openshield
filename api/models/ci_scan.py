"""Persistence layer for CI/CD scan results (GitHub AZ-CI-* rules).

``CIDatabase`` is intentionally thin: it wraps the same psycopg2 connection
pool that ``DatabaseManager`` uses, exposes only what the CI scan engine and
(in PR 3/3) the API routes need, and delegates pool management to the caller
exactly as ``DatabaseManager`` does — connect() / close() pair, with
``_get_conn()`` as the lazy accessor that enforces the connection is live.

Tables owned by this module (created in migration e1f2a3b4c5d6_ci_scans):
  ci_scans              — one row per scan invocation (owner + repo)
  ci_scan_evaluations   — one row per rule × resource × scan
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras

from api.models.finding import _get_pool  # re-use the shared pool

logger = logging.getLogger(__name__)


class CIDatabase:
    """Persist and retrieve CI/CD scan results.

    Lifecycle mirrors DatabaseManager:
        db = CIDatabase(dsn)
        db.connect()
        try:
            db.save_ci_scan(scan_id, owner, repo, evaluations)
        finally:
            db.close()
    """

    def __init__(self, dsn: Optional[str] = None) -> None:
        self.dsn: str = dsn or os.environ.get("DATABASE_URL", "")
        if not self.dsn:
            raise RuntimeError("CIDatabase requires a DSN or DATABASE_URL env var")
        self.conn: Any = None

    # ------------------------------------------------------------------ #
    # Connection                                                           #
    # ------------------------------------------------------------------ #

    def connect(self) -> None:
        """Acquire a connection from the shared pool."""
        self.conn = _get_pool(self.dsn).getconn()
        self.conn.autocommit = False
        logger.debug("CIDatabase: connection acquired from pool")

    def _get_conn(self) -> Any:
        if self.conn is None or self.conn.closed:
            self.connect()
        return self.conn

    def close(self) -> None:
        """Return the connection to the pool."""
        if self.conn is None:
            return
        try:
            _get_pool(self.dsn).putconn(self.conn, close=bool(self.conn.closed))
            logger.debug("CIDatabase: connection returned to pool")
        except Exception as exc:
            logger.error("CIDatabase: error returning connection to pool: %s", exc)
        finally:
            self.conn = None

    # ------------------------------------------------------------------ #
    # Write                                                                #
    # ------------------------------------------------------------------ #

    def create_pending_ci_scan(self, scan_id: str, owner: str, repo: str) -> None:
        """Insert a ci_scans row in the 'pending' state.

        Called before the engine starts so the scan is visible to callers
        immediately on trigger (PR 3/3 uses this for the 202 response).
        """
        started_at = datetime.now(timezone.utc)
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ci_scans (scan_id, owner, repo, started_at, status)
                VALUES (%s, %s, %s, %s, 'pending')
                ON CONFLICT (scan_id) DO NOTHING
                """,
                (scan_id, owner, repo, started_at),
            )
        conn.commit()
        logger.info("CIDatabase: created pending CI scan %s for %s/%s", scan_id, owner, repo)

    def save_ci_scan(
        self,
        scan_id: str,
        owner: str,
        repo: str,
        evaluations: List[Dict[str, Any]],
        error_message: Optional[str] = None,
    ) -> None:
        """Persist the completed CI scan header and all evaluation rows atomically.

        ``evaluations`` is a list of dicts matching ``RuleEvaluation.to_dict()``
        plus an optional ``"evidence"`` key.  The caller (CIScanEngine) is
        responsible for converting RuleEvaluation objects to dicts before
        calling this method.

        A retry of the same scan_id is safe: the header is upserted and
        evaluation rows are replaced wholesale (DELETE + INSERT inside the
        same transaction), so a retried scan converges on the current result
        rather than accumulating stale rows.
        """
        completed_at = datetime.now(timezone.utc)
        status = "failed" if error_message else "completed"
        fail_count = sum(1 for e in evaluations if e.get("status") == "FAIL")

        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO ci_scans (
                        scan_id, owner, repo, started_at, completed_at,
                        status, total_evaluations, fail_count, error_message
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (scan_id) DO UPDATE SET
                        completed_at       = EXCLUDED.completed_at,
                        status             = EXCLUDED.status,
                        total_evaluations  = EXCLUDED.total_evaluations,
                        fail_count         = EXCLUDED.fail_count,
                        error_message      = EXCLUDED.error_message
                    WHERE ci_scans.owner = EXCLUDED.owner
                      AND ci_scans.repo  = EXCLUDED.repo
                    """,
                    (
                        scan_id,
                        owner,
                        repo,
                        # started_at: keep existing value if the pending row
                        # already exists; use now() as fallback for direct calls.
                        completed_at,
                        completed_at,
                        status,
                        len(evaluations),
                        fail_count,
                        error_message,
                    ),
                )

                if cur.rowcount == 0:
                    raise ValueError(
                        f"scan_id {scan_id} already exists for a different repository; refusing to overwrite"
                    )

                # Replace evaluation rows atomically on retry — same pattern as
                # DatabaseManager.save_scan() for findings.
                cur.execute(
                    "DELETE FROM ci_scan_evaluations WHERE scan_id = %s",
                    (scan_id,),
                )

                evaluated_at = completed_at
                for ev in evaluations:
                    cur.execute(
                        """
                        INSERT INTO ci_scan_evaluations (
                            scan_id, rule_id, resource_id, resource_type,
                            status, reason_code, reason, evidence, evaluated_at
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (scan_id, rule_id, resource_id) DO UPDATE SET
                            resource_type = EXCLUDED.resource_type,
                            status        = EXCLUDED.status,
                            reason_code   = EXCLUDED.reason_code,
                            reason        = EXCLUDED.reason,
                            evidence      = EXCLUDED.evidence,
                            evaluated_at  = EXCLUDED.evaluated_at
                        """,
                        (
                            scan_id,
                            ev.get("rule_id"),
                            ev.get("resource_id"),
                            ev.get("resource_type", ""),
                            ev.get("status"),
                            ev.get("reason_code"),
                            ev.get("reason"),
                            json.dumps(ev.get("evidence", {})),
                            evaluated_at,
                        ),
                    )

            conn.commit()
        except Exception:
            conn.rollback()
            raise

        logger.info(
            "CIDatabase: saved CI scan %s (%s/%s) — %d evaluations, %d FAILs",
            scan_id,
            owner,
            repo,
            len(evaluations),
            fail_count,
        )

    def update_ci_scan_status(
        self,
        scan_id: str,
        status: str,
        error_message: Optional[str] = None,
    ) -> None:
        """Update the status of a CI scan (running → completed / failed)."""
        conn = self._get_conn()
        with conn.cursor() as cur:
            if status == "completed":
                completed_at = datetime.now(timezone.utc)
                cur.execute(
                    """
                    UPDATE ci_scans
                    SET status = %s, completed_at = %s, error_message = NULL
                    WHERE scan_id = %s
                    """,
                    (status, completed_at, scan_id),
                )
            else:
                cur.execute(
                    """
                    UPDATE ci_scans
                    SET status = %s,
                        error_message = %s,
                        completed_at = CASE WHEN %s::text = 'failed'
                                            THEN CURRENT_TIMESTAMP ELSE completed_at END
                    WHERE scan_id = %s
                    """,
                    (status, error_message, status, scan_id),
                )
        conn.commit()
        logger.info("CIDatabase: updated CI scan %s status to %s", scan_id, status)

    # ------------------------------------------------------------------ #
    # Read                                                                 #
    # ------------------------------------------------------------------ #

    def get_ci_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Return a single CI scan record by UUID, or None if not found."""
        conn = self._get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM ci_scans WHERE scan_id = %s", (scan_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_ci_scans(
        self,
        owner: Optional[str] = None,
        repo: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Return CI scan records, optionally filtered by owner/repo.

        Results are ordered most-recent-first. ``limit`` is capped at 100
        to match get_scans() in DatabaseManager.
        """
        conn = self._get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT * FROM ci_scans
                WHERE (%s IS NULL OR owner = %s)
                  AND (%s IS NULL OR repo  = %s)
                ORDER BY started_at DESC
                LIMIT %s
                """,
                (owner, owner, repo, repo, min(limit, 100)),
            )
            return [dict(row) for row in cur.fetchall()]

    def get_ci_scan_evaluations(self, scan_id: str) -> List[Dict[str, Any]]:
        """Return all evaluation rows for a CI scan, ordered by rule_id."""
        conn = self._get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT * FROM ci_scan_evaluations
                WHERE scan_id = %s
                ORDER BY rule_id, resource_id
                """,
                (scan_id,),
            )
            return [dict(row) for row in cur.fetchall()]
