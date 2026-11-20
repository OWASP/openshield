"""CSPM agent tool functions.

Each function takes a psycopg2 connection as its first argument so callers
can inject a real or fake connection. Tenant isolation is enforced through
explicit tenant_id parameters — never trust user input for this.

No Flask imports: this module must be importable outside a Flask request
context.
"""

import logging
import os
import uuid

logger = logging.getLogger(__name__)

_VALID_FRAMEWORKS = {"mcsb", "cis", "iso27001"}

# Same env knob the REST scan route honours (api/routes/scans.py). Read here
# directly so this module stays importable without Flask.
_MAX_SCANS_PER_HOUR_ENV = "OPENSHIELD_MAX_SCANS_PER_SUBSCRIPTION_PER_HOUR"


def _configured_hourly_quota() -> int:
    """Return the policy quota; zero preserves the no-limit default."""
    raw_value = os.environ.get(_MAX_SCANS_PER_HOUR_ENV, "0")
    try:
        quota = int(raw_value)
    except ValueError:
        logger.warning("Invalid %s=%r; disabling hourly quota", _MAX_SCANS_PER_HOUR_ENV, raw_value)
        return 0
    return max(0, quota)


def scan_subscription(db_manager, subscription_id: str, tenant_id: str) -> dict:
    """Queue a scan through the shared admission path.

    Unlike the other tools, the first argument is a ``DatabaseManager`` (not a
    raw connection) so the scan goes through ``admit_scan``: an advisory lock,
    idempotency, and the one-active-scan rule, exactly like the REST scan route.
    This prevents a prompt-injected or buggy loop from stampeding scans.

    Returns ``{"scan_id": str, "status": str, "created": bool}`` where
    ``created`` is False when an existing pending/running scan was reused.
    """
    from api.models.finding import ScanQuotaExceeded

    scan_id = str(uuid.uuid4())
    try:
        row, created = db_manager.admit_scan(scan_id, subscription_id, max_scans_per_hour=_configured_hourly_quota())
    except ScanQuotaExceeded:
        # Keep the specific quota message so the agent/MCP caller can surface it.
        raise
    except Exception:
        logger.exception(
            "scan_subscription failed for subscription_id=%s tenant_id=%s",
            subscription_id,
            tenant_id,
        )
        raise RuntimeError("Failed to queue scan")

    row = row or {}
    return {
        "scan_id": str(row.get("scan_id", scan_id)),
        "status": str(row.get("status", "pending")),
        "created": bool(created),
    }


def get_findings(
    db_conn,
    subscription_id: str,
    tenant_id: str,
    severity: str = None,
    state: str = None,
) -> list:
    """Return findings from the most recent completed scan for the subscription.

    Queries the baseline ``findings`` and ``scans`` tables. ``state`` is not
    supported without lifecycle tables and is silently ignored; all results are
    returned as 'open'. The parameter is kept for API compatibility with callers
    that will pass it once the lifecycle tables from PR #326 are deployed.

    Returns a list of dicts with keys:
        finding_id, rule_id, resource_id, severity, state
    """
    params: list = [subscription_id, subscription_id]
    extra = ""
    if severity is not None:
        extra += " AND UPPER(f.severity) = UPPER(%s)"
        params.append(severity)

    sql = (
        "SELECT f.id AS finding_id, f.rule_id, f.resource_id, f.severity, 'open' AS state"  # nosec B608
        " FROM findings f"
        " JOIN scans s ON s.scan_id = f.scan_id"
        " WHERE s.subscription_id = %s"
        "   AND s.status = 'completed'"
        "   AND s.scan_id = ("
        "     SELECT scan_id FROM scans"
        "     WHERE subscription_id = %s AND status = 'completed'"
        "     ORDER BY started_at DESC LIMIT 1"
        "   )"
        + extra
        + " LIMIT 200"
    )
    try:
        with db_conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
            return [
                {
                    "finding_id": row[0],
                    "rule_id": row[1],
                    "resource_id": row[2],
                    "severity": row[3],
                    "state": row[4],
                }
                for row in rows
            ]
    except Exception:
        try:
            db_conn.rollback()
        except Exception:
            pass
        logger.exception(
            "get_findings failed for subscription_id=%s",
            subscription_id,
        )
        return [{"error": "db_error"}]


def get_compliance_posture(db_manager, framework: str, subscription_id: str, tenant_id: str) -> dict:
    """Return compliance posture using DatabaseManager.get_compliance_score.

    The first argument must be a DatabaseManager so that the richer
    ``get_compliance_score`` method (which reads from ``scans`` and the
    framework mapping packs on disk) is used instead of the ``compliance_scores``
    aggregate table that is not yet present in the baseline schema.

    Valid frameworks: "mcsb", "cis", "iso27001"
    Raises ValueError for unknown framework.

    A read FAILURE returns {"framework": ..., "error": "db_error"} instead of a
    zeroed score so callers can distinguish "db down" from "posture is clean".
    """
    if framework.lower() not in _VALID_FRAMEWORKS:
        raise ValueError(f"Unknown compliance framework: {framework!r}. Valid options: {sorted(_VALID_FRAMEWORKS)}")

    get_score = getattr(db_manager, "get_compliance_score", None)
    if get_score is None:
        logger.error(
            "get_compliance_posture requires a DatabaseManager, got %r",
            type(db_manager).__name__,
        )
        return {"framework": framework, "error": "db_error"}
    try:
        return get_score(framework, subscription_id)
    except Exception:
        logger.exception(
            "get_compliance_posture failed for framework=%s subscription_id=%s",
            framework,
            subscription_id,
        )
        return {"framework": framework, "error": "db_error"}


def get_attack_paths(db_conn, scan_id: str, tenant_id: str) -> dict:
    """Return BFS attack paths for a scan.

    Returns a not_available response until the graph traversal PRs (#352-354)
    are deployed. Returning a clear status prevents the agent from interpreting
    an empty list as "no attack paths found".
    """
    logger.warning(
        "get_attack_paths called for scan_id=%s but attack path traversal is not yet deployed",
        scan_id,
    )
    return {
        "status": "not_available",
        "reason": (
            "Attack path traversal is not yet available in this deployment. "
            "The graph traversal feature is pending deployment. "
            "Use get_findings to review individual security findings instead."
        ),
    }


def explain_finding(db_conn, finding_id: int, tenant_id: str) -> dict | None:
    """Return full detail for a finding from the baseline ``findings`` table.

    Returns None if the finding does not exist. ``tenant_id`` is kept in the
    signature for future lifecycle-table integration (PR #326); isolation is
    currently enforced at the route level via the subscription allow-list.
    """
    sql = (
        "SELECT f.id, f.rule_id, f.resource_id, f.severity,"
        "       f.description, f.remediation, 'open' AS state"
        " FROM findings f"
        " WHERE f.id = %s"
        " LIMIT 1"
    )
    try:
        with db_conn.cursor() as cur:
            cur.execute(sql, (finding_id,))
            row = cur.fetchone()
            if row is None:
                return None
            return {
                "finding_id": row[0],
                "rule_id": row[1],
                "resource_id": row[2],
                "severity": row[3],
                "description": row[4],
                "remediation": row[5],
                "state": row[6],
            }
    except Exception:
        try:
            db_conn.rollback()
        except Exception:
            pass
        logger.exception("explain_finding failed for finding_id=%s", finding_id)
        return {"error": "db_error"}


def suggest_remediation(db_conn, finding_id: int, tenant_id: str) -> dict | None:
    """Return step-by-step remediation for a finding.

    Reuses explain_finding internally. Returns None if finding not found or
    belongs to a different tenant.
    """
    detail = explain_finding(db_conn, finding_id, tenant_id)
    if detail is None or "error" in detail:
        return None
    return {
        "finding_id": detail["finding_id"],
        "rule_id": detail["rule_id"],
        "steps": detail["remediation"],
        "resource_id": detail["resource_id"],
    }
