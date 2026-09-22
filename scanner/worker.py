"""
scanner/worker.py

Background worker process that polls the PostgreSQL database for pending
scans and executes them using ScanEngine.
"""

import logging
import os
import time
import traceback
from datetime import datetime, timezone

from api.models.finding import DatabaseManager
from api.observability import (
    PENDING_SCANS,
    SCAN_DURATION_SECONDS,
    SCANS_TOTAL,
    configure_logging,
    init_sentry,
)
from api.services.lifecycle_service import LifecycleService
from api.services.pattern_service import PatternService
from scanner.engine import ScanEngine

configure_logging()
logger = logging.getLogger("scanner.worker")

POLL_INTERVAL_SECONDS = 5


def run_worker():
    """Main worker loop."""
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        logger.error("DATABASE_URL environment variable is not set")
        return

    # Initialise Sentry only when SENTRY_DSN is configured (no-op otherwise).
    init_sentry()

    db = DatabaseManager(db_url)
    logger.info("OpenShield Background Worker started. Polling every %ds", POLL_INTERVAL_SECONDS)

    while True:
        try:
            # 1. Cleanup stale scans from previous crashes
            db.recover_stale_scans(timeout_minutes=60)

            # 2. Publish current queue depth
            PENDING_SCANS.set(len(db.get_pending_scans()))

            # 3. Atomic claim
            scan = db.claim_next_pending_scan()
            if not scan:
                time.sleep(POLL_INTERVAL_SECONDS)
                continue

            scan_id = str(scan["scan_id"])
            subscription_id = scan["subscription_id"]

            logger.info(
                "Starting scan %s for %s",
                scan_id,
                subscription_id,
                extra={"scan_id": scan_id},
            )

            scan_start = time.perf_counter()
            try:
                engine = ScanEngine(subscription_id)
                result = engine.run_scan(scan_id)

                # Update result with completion metadata
                result["completed_at"] = datetime.now(timezone.utc).isoformat()
                result["status"] = "completed"

                db.save_scan(result)

                # Apply lifecycle tracking. Lifecycle failures are non-fatal:
                # the scan is already persisted, so we log and continue rather
                # than marking the scan as failed.
                try:
                    tenant_id = os.environ.get("OPENSHIELD_TENANT_ID", subscription_id)
                    lc_svc = LifecycleService()
                    lc_svc.apply_scan(
                        db_conn=db._get_conn(),
                        scan_id=scan_id,
                        subscription_id=subscription_id,
                        tenant_id=tenant_id,
                        rule_outcomes=result.get("rule_outcomes", []),
                        findings=result.get("findings", []),
                    )
                    pat_svc = PatternService()
                    pat_svc.detect_and_publish(
                        db_conn=db._get_conn(),
                        scan_id=scan_id,
                        subscription_id=subscription_id,
                        tenant_id=tenant_id,
                    )
                except Exception as lc_exc:
                    logger.error(
                        "Lifecycle/pattern update failed for scan %s (scan data intact): %s",
                        scan_id,
                        lc_exc,
                        extra={"scan_id": scan_id},
                    )

                SCANS_TOTAL.labels(status="completed").inc()
                logger.info(
                    "Successfully completed scan %s",
                    scan_id,
                    extra={"scan_id": scan_id},
                )
            except Exception as exc:
                error_msg = f"{str(exc)}\n{traceback.format_exc()}"
                SCANS_TOTAL.labels(status="failed").inc()
                logger.error(
                    "Scan %s failed: %s",
                    scan_id,
                    error_msg,
                    extra={"scan_id": scan_id},
                )

                # Sanitize public error message
                public_error = "An internal error occurred during the scan. Please check the logs."
                db.update_scan_status(scan_id, "failed", error_message=public_error)
            finally:
                SCAN_DURATION_SECONDS.observe(time.perf_counter() - scan_start)

        except Exception as exc:
            logger.error("Worker loop encountered an error: %s", exc)
            time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    run_worker()
