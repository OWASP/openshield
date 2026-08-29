"""
scanner/worker.py

Background worker process that polls the PostgreSQL database for pending
scans and executes them using ScanEngine.
"""

import logging
import os
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone

from api.models.finding import DatabaseManager, LostLease
from api.observability import (
    PENDING_SCANS,
    SCAN_DURATION_SECONDS,
    SCANS_TOTAL,
    configure_logging,
    init_sentry,
)
from scanner.engine import ScanEngine
from scanner.enrichment_worker import process_enrichment_job

configure_logging()
logger = logging.getLogger("scanner.worker")

POLL_INTERVAL_SECONDS = 5
DEFAULT_LEASE_SECONDS = 15 * 60
DEFAULT_HEARTBEAT_SECONDS = 5 * 60


def _positive_seconds(name: str, default: int) -> int:
    """Read a positive interval without allowing malformed deploy config to stop work."""
    raw_value = os.environ.get(name)
    if raw_value is None:
        return default
    try:
        value = int(raw_value)
    except ValueError:
        logger.warning("Invalid %s=%r; using %d", name, raw_value, default)
        return default
    if value <= 0:
        logger.warning("Invalid %s=%r; using %d", name, raw_value, default)
        return default
    return value


def lease_configuration() -> tuple[int, int]:
    """Return a lease interval and a safely shorter heartbeat interval."""
    lease_seconds = _positive_seconds("SCAN_LEASE_SECONDS", DEFAULT_LEASE_SECONDS)
    heartbeat_seconds = _positive_seconds("SCAN_HEARTBEAT_SECONDS", DEFAULT_HEARTBEAT_SECONDS)
    if heartbeat_seconds >= lease_seconds:
        heartbeat_seconds = max(1, lease_seconds // 3)
        logger.warning(
            "SCAN_HEARTBEAT_SECONDS must be less than SCAN_LEASE_SECONDS; using %d seconds",
            heartbeat_seconds,
        )
    return lease_seconds, heartbeat_seconds


class LeaseHeartbeat:
    """Renew one claim through a dedicated database connection.

    Scan execution may block on Azure calls.  The heartbeat intentionally owns
    a separate DatabaseManager so it never shares a psycopg connection with
    the worker's final persistence transaction.
    """

    def __init__(
        self,
        db_url: str,
        scan_id: str,
        lease_owner: str,
        fencing_token: int,
        lease_seconds: int,
        heartbeat_seconds: int,
    ) -> None:
        self.db_url = db_url
        self.scan_id = scan_id
        self.lease_owner = lease_owner
        self.fencing_token = fencing_token
        self.lease_seconds = lease_seconds
        self.heartbeat_seconds = heartbeat_seconds
        self.lost = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name=f"scan-heartbeat-{scan_id}", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> bool:
        """Stop the heartbeat, reporting whether its thread actually exited."""
        self._stop.set()
        self._thread.join(timeout=10)
        if self._thread.is_alive():
            logger.critical("Heartbeat thread for scan %s did not stop promptly", self.scan_id)
            return False
        return True

    def _run(self) -> None:
        db = DatabaseManager(self.db_url)
        try:
            while not self._stop.wait(self.heartbeat_seconds):
                try:
                    db.heartbeat_scan(
                        self.scan_id,
                        self.lease_owner,
                        self.fencing_token,
                        self.lease_seconds,
                    )
                except LostLease:
                    self.lost.set()
                    logger.warning(
                        "Lease lost while scan %s was executing", self.scan_id, extra={"scan_id": self.scan_id}
                    )
                    return
                except Exception as exc:
                    # A transient DB failure must be visible and the next
                    # heartbeat must get a clean/reacquired connection.
                    logger.error("Heartbeat failed for scan %s: %s", self.scan_id, exc, exc_info=True)
                    db.rollback()
        finally:
            db.close()


def run_worker():
    """Main worker loop."""
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        logger.error("DATABASE_URL environment variable is not set")
        return

    # Initialise Sentry only when SENTRY_DSN is configured (no-op otherwise).
    init_sentry()

    db = DatabaseManager(db_url)
    worker_id = str(uuid.uuid4())
    lease_seconds, heartbeat_seconds = lease_configuration()
    logger.info("OpenShield Background Worker started. Polling every %ds", POLL_INTERVAL_SECONDS)

    while True:
        try:
            db.record_worker_heartbeat(worker_id, "scan")
            # This process executes both durable queue types; record both
            # liveness signals without exporting the worker UUID as a label.
            db.record_worker_heartbeat(worker_id, "enrichment")
            # 1. Cleanup stale scans from previous crashes
            db.recover_stale_scans()
            db.recover_stale_enrichment_jobs()

            # 2. Publish current queue depth
            PENDING_SCANS.set(len(db.get_pending_scans()))

            # 3. Run one durable enrichment job before taking another scan.
            enrichment_job = db.claim_next_enrichment_job(worker_id, lease_seconds)
            if enrichment_job:
                process_enrichment_job(db, enrichment_job, worker_id, lease_seconds)
                continue

            # 4. Atomic scan claim
            scan = db.claim_next_pending_scan(worker_id, lease_seconds)
            if not scan:
                time.sleep(POLL_INTERVAL_SECONDS)
                continue

            scan_id = str(scan["scan_id"])
            subscription_id = scan["subscription_id"]
            fencing_token = scan["fencing_token"]

            logger.info(
                "Starting scan %s for %s",
                scan_id,
                subscription_id,
                extra={"scan_id": scan_id},
            )

            scan_start = time.perf_counter()
            heartbeat = LeaseHeartbeat(
                db_url,
                scan_id,
                worker_id,
                fencing_token,
                lease_seconds,
                heartbeat_seconds,
            )
            heartbeat.start()
            try:
                engine = ScanEngine(subscription_id)
                result = engine.run_scan(scan_id)

                # Update result with completion metadata
                result["completed_at"] = datetime.now(timezone.utc).isoformat()
                result["status"] = "completed"

                if not heartbeat.stop():
                    # Do not start another scan while a database call in this
                    # heartbeat is still stuck; process supervision can restart
                    # us and the unconfirmed claim will safely expire.
                    return
                if heartbeat.lost.is_set():
                    raise LostLease(f"Scan {scan_id} lost its lease before completion")
                db.save_scan(result, worker_id, fencing_token)
                SCANS_TOTAL.labels(status="completed").inc()
                logger.info(
                    "Successfully completed scan %s",
                    scan_id,
                    extra={"scan_id": scan_id},
                )
            except LostLease:
                if not heartbeat.stop():
                    return
                logger.warning("Scan %s finished after its lease was lost; no result was persisted", scan_id)
            except Exception as exc:
                if not heartbeat.stop():
                    return
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
                try:
                    db.update_scan_status(
                        scan_id,
                        "failed",
                        error_message=public_error,
                        lease_owner=worker_id,
                        fencing_token=fencing_token,
                    )
                except LostLease:
                    logger.warning("Scan %s failed after its lease was lost; failure was not persisted", scan_id)
            finally:
                heartbeat.stop()
                SCAN_DURATION_SECONDS.observe(time.perf_counter() - scan_start)

        except Exception as exc:
            logger.error("Worker loop encountered an error: %s", exc)
            db.rollback()
            time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    run_worker()
