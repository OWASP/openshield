"""Durable lifecycle application job execution for the scan worker."""

import logging
import os

from api.models.finding import DatabaseManager, LostLease
from api.services.lifecycle_service import LifecycleService
from api.services.pattern_service import PatternService

logger = logging.getLogger("scanner.lifecycle_worker")


def process_lifecycle_job(
    db: DatabaseManager,
    job: dict,
    lease_owner: str,
    lease_seconds: int,
    *,
    max_attempts: int = 3,
) -> str:
    """Apply lifecycle state for a scan's findings under a fenced job claim.

    Returns one of: "completed", "lost_lease", "failed", "retry".
    """
    job_id = str(job["job_id"])
    scan_id = str(job["scan_id"])
    fencing_token = job["fencing_token"]

    try:
        conn = db._get_conn()
        # Hold the fenced job row until lifecycle, patterns and completion all
        # commit. Recovery uses SKIP LOCKED and cannot reclaim an active writer.
        with conn.cursor() as cur:
            cur.execute(
                "SELECT job_id FROM lifecycle_jobs WHERE job_id=%s AND status='running' "
                "AND lease_owner=%s AND fencing_token=%s AND lease_expires_at > clock_timestamp() FOR UPDATE",
                (job_id, lease_owner, fencing_token),
            )
            if cur.fetchone() is None:
                raise LostLease(f"Lifecycle job {job_id} is no longer owned by this worker")
        scan = db.get_scan(scan_id)
        if scan is None:
            logger.error("Lifecycle job %s: scan %s not found", job_id, scan_id)
            db.complete_lifecycle_job(job_id, lease_owner, fencing_token)
            return "completed"

        subscription_id = scan.get("subscription_id", "")
        tenant_id = (os.environ.get("OPENSHIELD_TENANT_ID") or os.environ.get("AZURE_TENANT_ID") or "").strip().lower()
        if not tenant_id:
            raise ValueError("OPENSHIELD_TENANT_ID or AZURE_TENANT_ID is required for lifecycle scope")

        rule_outcomes = scan.get("rule_outcomes_json") or []
        findings = db.get_lifecycle_findings(scan_id)
        evaluations = db.get_rule_evaluations(scan_id)
        snapshot = scan.get("compliance_mapping_snapshot") or {}
        failed_rule_ids = set((snapshot.get("_scan_rule_outcomes") or {}).get("failed_rule_ids") or [])

        lc_svc = LifecycleService()
        applied = lc_svc.apply_scan(
            db_conn=conn,
            scan_id=scan_id,
            subscription_id=subscription_id,
            tenant_id=tenant_id,
            rule_outcomes=rule_outcomes,
            findings=findings,
            evaluations=evaluations,
            failed_rule_ids=failed_rule_ids,
            commit=False,
        )

        if applied:
            pat_svc = PatternService()
            pat_svc.detect_and_publish(
                db_conn=conn,
                scan_id=scan_id,
                subscription_id=subscription_id,
                tenant_id=tenant_id,
                commit=False,
            )

        db.complete_lifecycle_job(job_id, lease_owner, fencing_token)
        logger.info("Completed lifecycle job %s for scan %s", job_id, scan_id)
        return "completed"

    except LostLease:
        db.rollback()
        logger.warning("Lifecycle job %s lost its lease", job_id)
        return "lost_lease"
    except Exception as exc:
        db.rollback()
        retry_seconds = min(300, 30 * (2 ** max(0, job["attempt_count"] - 1)))
        outcome = db.fail_lifecycle_job(
            job_id,
            lease_owner,
            fencing_token,
            "Lifecycle application failed; see worker logs for details.",
            max_attempts=max_attempts,
            retry_seconds=retry_seconds,
        )
        logger.error("Lifecycle job %s failed (%s): %s", job_id, outcome, exc, exc_info=True)
        return outcome
