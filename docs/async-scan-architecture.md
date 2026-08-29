# Asynchronous Scan Architecture

## Overview

OpenShield uses an asynchronous execution model for Azure posture scans. This architecture ensures the system can handle large subscriptions with thousands of resources without hitting web server timeouts or degrading frontend performance.

## The Problem: Synchronous Bottlenecks

In the legacy synchronous model, POST /api/scans/trigger would block the HTTP request until the scan completed. For large environments, this led to several critical issues. First, Gunicorn or load balancer timeouts would kill the scan mid execution. Second, web workers were tied up for minutes, preventing other users from accessing the dashboard. Third, the UI would hang or show generic Network Error messages while waiting for the response.

## The Solution: DB Backed Background Worker

OpenShield now employs a decoupled, database backed worker architecture. This is the industry standard for long running security tasks where reliability and state persistence are critical.

### 1. The API (Flask)
When a scan is triggered, the API performs minimal work. It validates the subscription_id, creates a record in the scans table with status set to pending, and returns 202 Accepted and the scan_id immediately.

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

### 3. The Worker (Python)
The scanner/worker.py process runs independently of the web server. Its lifecycle involves several steps. It atomically claims a pending scan, starts a dedicated lease-heartbeat connection, and invokes `ScanEngine.run_scan(scan_id)`. Completion and failure are fenced database transactions: they only succeed when the current worker still owns the same unexpired token. On success, it persists findings and marks the scan complete atomically. On failure, it records a sanitized error only while it still owns the lease.

## Technical Rationale

### Why not Celery or Redis
While Celery is powerful, it introduces external dependencies and operational complexity. CSPM scans are macro tasks taking minutes rather than milliseconds. A database backed model is more resilient for these workloads because the state is persisted at the source of truth in PostgreSQL.

### Why not Threading
Python background threads are ephemeral. If the web server process restarts, all in flight scans are killed instantly and marked as running forever in the DB. A separate worker process ensures that the scan lifecycle is independent of the web server lifecycle.

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
