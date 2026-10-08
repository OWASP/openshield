# OpenShield - CVE Correlation Feature Documentation

## Overview

The CVE Correlation feature integrates the MITRE National Vulnerability Database (NVD) API with the OpenShield scanner. It cross-references security misconfigurations discovered during scans with known Common Vulnerabilities and Exposures (CVEs), providing users with CVSS scores and exploit availability status.

## Files Created and Modified

### New Files (Core Logic)

| File | Purpose |
|---|---|
| scanner/nvd_client.py | NVD API Integration. Handles low-level communication with MITRE NVD. Implements strict rate-limiting (7s gap), in-memory caching for performance, and exponential back-off for reliability. |
| scanner/cve_correlator.py | Contextual Mapping. Maps OpenShield Rule IDs (e.g., AZ-STOR) to NVD search terms. Performs the logic of merging raw API results into finding objects. |
| tests/test_cve_correlator.py | Logic Verification. Unit tests ensuring Rule IDs map correctly and finding enrichment correctly identifies the highest risk. |

### Modified Files (Integration)

| File | Change | Why |
|---|---|---|
| scanner/engine.py | Decoupled Scan. Removed synchronous enrichment from the scan lifecycle. | Performance: Azure scans now return immediately without waiting for NVD rate limits (7s per resource type). |
| api/routes/scans.py | Durable endpoint. `POST /api/scans/<scan_id>/enrich` enqueues or returns a PostgreSQL job. | No Gunicorn daemon thread owns authoritative work. |
| scanner/enrichment_worker.py | Checkpointed durable enrichment execution. | Reclaims expired work safely and resumes at a finding checkpoint. |
| api/models/finding.py | Updated Scan model and added enrichment status tracking. | Persistence: Adds `cve_enrichment_status` to track `PENDING`, `COMPLETED`, or `FAILED` states. |
| alembic/versions/ | Defines CVE columns in the versioned database schema. | Deployment: Alembic owns schema changes independently of Flask application startup. |
| api/routes/score.py | Added GET /api/score/cve-summary endpoint. | Dashboard UI: Provides the frontend with high-level data like Total Known Exploits and enrichment status. |
| api/routes/findings.py | Returns findings from the database without JIT enrichment. | Performance: Ensures predictable and fast API responses for findings. |

## Frontend Integration Design

To ensure the frontend dashboard works perfectly, the architecture uses a Decoupled Enrichment model:

1. Fast Dashboard Loads: The scan engine completes rapidly. The dashboard can check the enrichment status of the latest scan.
2. Durable Enrichment: Completion creates one job; `POST /api/scans/<scan_id>/enrich` returns that job idempotently. The worker claims, retries, and checkpoints it in PostgreSQL.
3. Dashboard-Ready Summary Endpoint: The /api/score/cve-summary endpoint includes the `status` field, allowing the UI to show a "Scan Enriched" badge or a "Pending" spinner.
4. Actionable Risk (CISA KEV): The exploit_available flag uses the CISA Known Exploited Vulnerabilities catalogue, allowing the dashboard to highlight high-priority risks that are being exploited in the wild.
5. Persistent Historical State: Enrichment checkpoint state and results survive API/worker restarts. NVD pagination continues through every `totalResults` page.

## Security and Compliance Audit

1. No Hardcoded Secrets: All credentials (DATABASE_URL, JWT_SECRET) are handled via environment variables.
2. SSRF Protection: NVD query parameters are sanitized and derived from internal static maps.
3. SQL Safety: All database additions use parameterized queries to prevent injection.
4. Character Quality: All non-ASCII characters and emojis were removed for pipeline compatibility.

## Frontend-Ready API Responses

### GET /api/findings

Response shape (abridged):

```json
{
   "count": 2,
   "findings": [
      {
         "id": 123,
         "rule_id": "AZ-STOR-003",
         "severity": "HIGH",
         "resource_id": "/subscriptions/...",
         "cve_references": [],
         "cvss_score": null,
         "exploit_available": false
      }
   ]
}
```

Notes:
1. Results are ordered by detected_at descending and capped at 1000.
2. CVE fields are present but empty if enrichment has not been triggered.

### GET /api/score/cve-summary

Response shape:

```json
{
   "status": "COMPLETED",
   "total_findings": 74,
   "exploit_count": 5,
   "max_cvss_score": 9.8,
   "avg_cvss_score": 6.42,
   "critical_cve_count": 3
}
```

## Testing Strategy

All logic is verified using the Python standard library unittest framework. All NVD HTTP calls are fully mocked to ensure stability.

### Testing Rationale

The tests focus on the correlator behavior with all NVD calls mocked:

1. Keyword Mapping (TestGetNvdKeyword):
   * Purpose: Ensure rule_id values resolve to a stable NVD keyword.
   * Rationale: Prefix fallback prevents gaps when new rules are added.

2. Enrichment Logic (TestEnrichSingleFinding, TestEnrichFindings):
   * Purpose: Validate cve_references, cvss_score, and exploit_available handling.
   * Rationale: Ensures highest CVSS is selected and output order is preserved.

### How to run the tests

```bash
python3 -m unittest tests/test_cve_correlator.py -v
```

Expected output: All tests passing, zero network calls made.
