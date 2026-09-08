# Asynchronous Scan Architecture

## Overview

OpenShield uses an asynchronous execution model for Azure posture scans. This architecture ensures the system can handle large subscriptions with thousands of resources without hitting web server timeouts or degrading frontend performance.

## The Problem: Synchronous Bottlenecks

In the legacy synchronous model, POST /api/scans/trigger would block the HTTP request until the scan completed. For large environments, this led to several critical issues. First, Gunicorn or load balancer timeouts would kill the scan mid execution. Second, web workers were tied up for minutes, preventing other users from accessing the dashboard. Third, the UI would hang or show generic Network Error messages while waiting for the response.

## The Solution: DB Backed Background Worker

OpenShield now employs a decoupled, database backed worker architecture. This is the industry standard for long running security tasks where reliability and state persistence are critical.

### 1. The API (Flask)
When a scan is triggered, the API validates the subscription and creates a durable pending record. PostgreSQL permits at most one `pending` or `running` scan per subscription. `Idempotency-Key` replays return the same logical scan when the request fingerprint matches; reuse with different semantics returns a conflict. The optional `OPENSHIELD_MAX_SCANS_PER_SUBSCRIPTION_PER_HOUR` policy enables an explicit time-window quota. A zero/unset value preserves the current no-business-limit policy while the one-active-scan concurrency quota remains enforced.

### 2. The Queue (PostgreSQL)
The scans table acts as a persistent task queue. This avoids the need for additional infrastructure like Redis or RabbitMQ while providing ACID compliance, visibility, and auditability. Scan states are never lost during crashes, status polling is a simple SQL query, and every scan has a persistent record of its error state.

### Render restart behavior
Scan state is not stored in Flask memory. `POST /api/scans/trigger` inserts a `pending` row into PostgreSQL, and `GET /api/scans/<scan_id>` reads that same row back from PostgreSQL. If the Render web process restarts, queued scan state remains in the database and the dashboard can continue polling by `scan_id` after the app process comes back.

Each claim is a renewable lease. The worker records a process-lifetime owner ID,
an expiry time, and a monotonically increasing fencing token, then renews the
lease while Azure work is running. `recover_stale_scans()` only requeues work
after its lease expires; a healthy worker is never reclaimed solely because its
original claim is old. A reclaimed scan receives a new token, so the previous
worker cannot persist completion, failure, or findings after it loses ownership.
Once a scan reaches the maximum attempt count, it is marked `failed` so bad
credentials or persistent Azure errors cannot retry forever.

Findings use a stable database-enforced identity (`scan`, rule, canonical
resource scope, and an optional rule-specific discriminator). Result retries
use PostgreSQL upserts, so mutable text or severity is updated rather than
creating a second authoritative finding. Per-resource rule evaluations are a
separate contract (issue #263) and are not persisted by this architecture yet;
when they land, they are written inside the same fenced completion transaction
and inherit its ownership check.

### 3. The Worker (Python)
The scanner/worker.py process runs independently of the web server. It atomically claims a pending scan, starts a dedicated lease-heartbeat connection, and invokes `ScanEngine.run_scan(scan_id)`. Completion and failure are fenced database transactions: they only succeed when the current worker still owns the same unexpired token. On success, it persists findings and one durable enrichment job atomically. On failure, it records a sanitized error only while it still owns the lease.

### Durable CVE enrichment

`POST /api/scans/<scan_id>/enrich` enqueues (or returns) the one durable PostgreSQL enrichment job for the scan; it never starts a request-owned daemon thread. The scan worker claims those jobs with the same owner/expiry/fencing model, checkpoints after each finding, and retries transient failures with bounded exponential backoff. An expired job is recovered or terminally failed after its attempt limit. NVD retrieval follows every `totalResults` page; replaying a checkpoint updates the existing finding instead of duplicating CVE data.

A job that exhausts its retries becomes `failed`. Re-POSTing the endpoint is the supported recovery path: it atomically returns that job to `pending` with a fresh retry budget while keeping the same job row, its last `error_message`, and its `checkpoint`. A `running` job with a live lease is never disturbed by a re-POST — only lease expiry can move it — and a `completed` job is never restarted. See [api-reference.md](api-reference.md) for the exact response contract.

### Worker scheduling

One worker process serves both durable queues. Each loop iteration takes **at most one** enrichment job and **at most one** scan, so neither queue can starve the other no matter how deep either gets: a large enrichment backlog delays scans by one job per iteration rather than blocking them until it drains. An iteration that did any work polls again immediately; only a completely idle iteration sleeps for the poll interval.

### Operational signals

`/metrics` derives bounded-cardinality operational gauges from PostgreSQL: worker heartbeat age, oldest queue age, oldest active lease age, aggregate retry attempts, and the last successful scan timestamp. Labels are limited to `queue` (`scan` or `enrichment`) and `worker_type`; scan, job, subscription, and worker identifiers are never metric labels.

These gauges are recomputed on every scrape rather than cached. The queue, lease and heartbeat aggregates are served by partial indexes and touch only active rows; the last-successful-scan lookup is served by a partial index on completed scans. The two `retry_attempts` sums scan their whole table and therefore grow with scan history — acceptable at current volumes, and the thing to revisit first (a short-TTL in-process cache) if `/metrics` scrape latency ever becomes visible.

Worker identities are per-process, so `worker_heartbeats` would otherwise gain a permanent row on every restart. Rows older than `WORKER_HEARTBEAT_RETENTION_SECONDS` (default 7 days) are pruned on the heartbeat that registers a new worker identity — once per worker process, never on every beat. Retention is far longer than any heartbeat interval, so a live worker is never pruned.

## Technical Rationale

### Why not Celery or Redis
While Celery is powerful, it introduces external dependencies and operational complexity. CSPM scans are macro tasks taking minutes rather than milliseconds. A database backed model is more resilient for these workloads because the state is persisted at the source of truth in PostgreSQL.

### Why not Threading
Python background threads are ephemeral. If the web server process restarts, all in flight scans are killed instantly and marked as running forever in the DB. A separate worker process ensures that the scan lifecycle is independent of the web server lifecycle.

## Deployment order

This release is not safe for mixed old and new scan workers. Stop or drain old
workers, apply Alembic migrations, then start the fenced worker version. Legacy
workers do not carry ownership/fencing state; legacy running scans are retained
and made recoverable by the lease migration rather than deleted.

### Migration prerequisite: one active scan per subscription

`a7c5e9d2f1b4` adds the unique index that enforces one `pending`/`running` scan
per subscription. A deployment that predates that rule may already hold several,
in which case the migration **stops before creating any index** and names the
offending subscriptions:

```
Cannot enforce one active scan per subscription: 1 subscription(s) already have
more than one pending/running scan: <subscription-id> (2 active). ...
```

Nothing is changed when this happens — the migration will not decide which of
your production scans is authoritative. Resolve it, then re-run:

1. Drain the old workers first (step 1 above), so no new active scans appear.
2. Let the in-flight scans finish, or mark the superseded rows `failed`
   (`UPDATE scans SET status = 'failed', error_message = '...' WHERE scan_id = ...`).
   Never delete the rows: scan history is retained, and only `pending`/`running`
   rows are constrained — any number of `completed`/`failed` scans per
   subscription remains valid.
3. Re-run `alembic upgrade head`. A retry is safe: the migration drops the
   INVALID index that an interrupted `CREATE INDEX CONCURRENTLY` leaves behind
   before rebuilding it.

## Testing Suite

The asynchronous transition is verified through a multi layered testing strategy.

### 1. Unit Tests
Located in tests/test_cve_correlator.py, tests/test_nvd_client.py, and tests/test_worker.py. These tests verify the core logic in isolation by mocking all network calls to Azure and NVD.

### 2. Smoke Tests
Located in tests/smoke_test.py. These tests verify the full integration. TC 13 verifies POST /api/scans/trigger returns 202 Accepted. TC 14 verifies the response contains a valid scan_id. TC 40 verifies that GET /api/scans/scan_id returns a valid status object, enabling frontend polling.

### 3. CI Validation
The ci checks job in .github/workflows/ci.yml ensures that worker syntax is valid, new database methods maintain schema integrity, and cross references between compliance mappings and rule files remain intact.

## Integrating with the Frontend

The frontend should follow this pattern for a smooth user experience. Call POST /api/scans/trigger. Extract the scan_id. Show a Scan Queued notification. Poll GET /api/scans/scan_id every 5 to 10 seconds until status is completed or failed. Refresh the dashboard once the status is completed.
