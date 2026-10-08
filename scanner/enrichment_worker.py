"""Durable CVE enrichment job execution for the scan worker."""

import logging

from api.models.finding import DatabaseManager, LostLease
from scanner.cve_correlator import enrich_finding_durable


logger = logging.getLogger("scanner.enrichment_worker")


def process_enrichment_job(
    db: DatabaseManager,
    job: dict,
    lease_owner: str,
    lease_seconds: int,
    *,
    max_attempts: int = 3,
) -> str:
    """Run a claimed job, checkpointing each finding under its fence.

    A restart resumes at the stored finding offset. Replaying the last item is
    safe because persistence updates the existing finding row by primary key.
    """
    job_id = str(job["job_id"])
    fencing_token = job["fencing_token"]
    try:
        findings = db.get_enrichment_findings(str(job["scan_id"]))
        for index, finding in enumerate(findings[job["checkpoint"] :], start=job["checkpoint"]):
            db.heartbeat_enrichment_job(job_id, lease_owner, fencing_token, lease_seconds)
            enriched = enrich_finding_durable(finding)
            db.persist_enrichment_progress(job_id, lease_owner, fencing_token, enriched, index + 1)
        db.complete_enrichment_job(job_id, lease_owner, fencing_token)
        logger.info("Completed enrichment job %s", job_id)
        return "completed"
    except LostLease:
        logger.warning("Enrichment job %s lost its lease; no further writes attempted", job_id)
        return "lost_lease"
    except Exception as exc:
        retry_seconds = min(300, 30 * (2 ** max(0, job["attempt_count"] - 1)))
        outcome = db.fail_enrichment_job(
            job_id,
            lease_owner,
            fencing_token,
            "CVE enrichment failed; see worker logs for details.",
            max_attempts=max_attempts,
            retry_seconds=retry_seconds,
        )
        logger.error("Enrichment job %s failed (%s): %s", job_id, outcome, exc, exc_info=True)
        return outcome
