# API Reference

The OpenShield API is a Flask app registered in `api/app.py`. By default, every
`/api/*` route requires an `Authorization: Bearer <jwt>` header signed with
`JWT_SECRET`; only the explicitly listed health and observability endpoints are
public. Read-only API routes become public only when the deliberate demo-mode
setting is enabled.

## Authentication

`/`, `/health`, `/ready`, and `/metrics` are always public. All other routes — including all `/api/*` GET endpoints — require an `Authorization: Bearer <jwt>` header signed with `JWT_SECRET`.

Every accepted token must carry:

- `exp` — a token with no expiry is rejected outright. There is no way to mint a permanently-valid token; regenerate before it expires.
- `role` — one of `viewer`, `operator`, or `admin`. A missing or unrecognized role is treated the same as an invalid signature (`401`).

`viewer` is read-only: any non-`GET`/`HEAD` request (scan trigger, AI endpoints) from a `viewer` token is rejected with `403`, regardless of demo mode. Only `operator` and `admin` may perform a write. This is enforced in `api/app.py`'s JWT middleware, not per-route, so it applies uniformly to every current and future write endpoint.

`scripts/generate_demo_jwt.py` mints a `viewer` token with a bounded expiry (`DEMO_JWT_TTL_HOURS`, default 24h) — see the script's own docstring before embedding one as `VITE_JWT_TOKEN`.

### Subscription authorization

`POST /api/scans/trigger` also checks `subscription_id` against `OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS`, a comma-separated allowlist. A valid `operator`/`admin` token can otherwise trigger a scan against *any* subscription_id — role alone doesn't say which subscription a caller is entitled to. Left unset, every subscription_id is accepted (matches historical behavior); the API logs a loud startup warning when it's unset. This is a single-tenant containment boundary, not a substitute for real per-tenant authorization — see issue #294 for the full multi-tenant/OIDC scope this is a stopgap for.

## Input limits

- Request bodies are limited to 2 MiB.
- Scan and subscription identifiers use canonical UUID format.
- Finding filters accept only `severity`, `category`, `rule_id`, and `scan_id`;
  unknown or repeated parameters return `400`.
- AI routes accept a supported provider, an API key of at most 4,096 characters,
  an optional model identifier of at most 128 characters, questions of at most
  4,000 characters, and at most 1,000 finding objects.
- Full boundary details are maintained in `docs/input-validation-audit.md`.

### Public demo mode

Set `OPENSHIELD_PUBLIC_DEMO=true` to allow unauthenticated GET requests to `/api/*`. This is intended for local development and public demo dashboards where the data is not sensitive. POST endpoints (scan trigger, AI) always require a valid JWT regardless of this setting.

| Environment variable | Value | GET /api/* behavior |
|---|---|---|
| `OPENSHIELD_PUBLIC_DEMO` | not set or `false` | JWT required (default) |
| `OPENSHIELD_PUBLIC_DEMO` | `true` | public, no JWT needed |

Do not enable `OPENSHIELD_PUBLIC_DEMO` in a deployment that holds real Azure scan data.
---

## GET /health

Health check for the API process.

Query parameters: none

Example response:

```json
{
  "status": "ok"
}
```

---

## GET /api/findings

Returns findings, optionally filtered by severity, category, rule ID, or scan ID.

Query parameters:

| Name | Description |
|---|---|
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` (`INFORMATIONAL` is normalized to `INFO`) |
| `category` | Rule category, such as `Storage`, `Network`, `Identity`, `Database`, `Compute`, or `Key Vault` |
| `rule_id` | Rule ID, such as `AZ-STOR-001` |
| `scan_id` | UUID of a specific scan |

Example response:

```json
{
  "count": 1,
  "findings": [
    {
      "id": 42,
      "scan_id": "6f4a08ac-7d3a-4d9a-a4b4-2a26e5f63c8a",
      "rule_id": "AZ-STOR-001",
      "rule_name": "Public Blob Access Enabled on Storage Account",
      "severity": "HIGH",
      "category": "Storage",
      "resource_id": "/subscriptions/example/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/example",
      "resource_name": "example",
      "resource_type": "Microsoft.Storage/storageAccounts",
      "description": "Storage accounts with public blob access enabled allow unauthenticated read access to blob data over the internet.",
      "remediation": "Disable public blob access on the storage account.",
      "playbook": "playbooks/cli/fix_az_stor_001.sh",
      "frameworks": {
        "CIS": "3.5",
        "NIST": "PR.AC-3",
        "ISO27001": "A.9.4.1"
      },
      "metadata": {},
      "detected_at": "2026-05-09T12:00:00Z"
    }
  ]
}
```

---

## GET /api/findings/&lt;finding_id&gt;

Returns one finding by integer ID.

Query parameters: none

Example response:

```json
{
  "id": 42,
  "scan_id": "6f4a08ac-7d3a-4d9a-a4b4-2a26e5f63c8a",
  "rule_id": "AZ-STOR-001",
  "rule_name": "Public Blob Access Enabled on Storage Account",
  "severity": "HIGH",
  "category": "Storage",
  "resource_id": "/subscriptions/example/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/example",
  "resource_name": "example",
  "resource_type": "Microsoft.Storage/storageAccounts",
  "description": "Storage accounts with public blob access enabled allow unauthenticated read access to blob data over the internet.",
  "remediation": "Disable public blob access on the storage account.",
  "playbook": "playbooks/cli/fix_az_stor_001.sh",
  "frameworks": {
    "CIS": "3.5",
    "NIST": "PR.AC-3",
    "ISO27001": "A.9.4.1"
  },
  "metadata": {},
  "detected_at": "2026-05-09T12:00:00Z"
}
```

Not found response:

```json
{
  "error": "Finding not found"
}
```

---

## GET /api/scans

Returns historical scan records ordered by most recent first.

Query parameters: none

Example response:

```json
{
  "count": 1,
  "scans": [
    {
      "scan_id": "6f4a08ac-7d3a-4d9a-a4b4-2a26e5f63c8a",
      "subscription_id": "00000000-0000-0000-0000-000000000000",
      "started_at": "2026-05-09T12:00:00Z",
      "completed_at": "2026-05-09T12:02:00Z",
      "total_findings": 3
    }
  ]
}
```

---

## GET /api/scans/&lt;scan_id&gt;

Returns the details and current status of a specific scan.

Path parameters: `scan_id` — UUID of the scan.

Example response:

```json
{
  "scan_id": "6f4a08ac-7d3a-4d9a-a4b4-2a26e5f63c8a",
  "subscription_id": "00000000-0000-0000-0000-000000000000",
  "status": "completed",
  "started_at": "2026-05-09T12:00:00Z",
  "completed_at": "2026-05-09T12:02:00Z",
  "total_findings": 3,
  "score": 85,
  "error_message": null
}
```

---

## POST /api/scans/trigger

Triggers an asynchronous scan against the configured subscription. Returns `202 Accepted` with the `scan_id` immediately. The actual scan execution happens in a background worker process.

Request body:

```json
{
  "subscription_id": "00000000-0000-0000-0000-000000000000"
}
```

Example response:

```json
{
  "scan_id": "6f4a08ac-7d3a-4d9a-a4b4-2a26e5f63c8a",
  "status": "pending",
  "message": "Scan has been queued and will start shortly."
}
```

Missing subscription response:

```json
{
  "error": "subscription_id is required"
}
```

---

## GET /api/score

Returns the overall security posture score from 0 to 100. Under [severity contract v1](severity-contract.md), the score starts at 100 and deducts 20 per CRITICAL finding, 10 per HIGH finding, 5 per MEDIUM finding, and 2 per LOW finding. INFO findings deduct zero.

Query parameters: none

Example response:

```json
{
  "score": 82,
  "max_score": 100
}
```

---

## GET /api/compliance/&lt;framework&gt;

Returns a pass/fail control breakdown for a supported compliance framework.

Supported frameworks:

| Path value | Framework file |
|---|---|
| `cis` | `cis_azure_benchmark.json` |
| `nist` | `nist_csf.json` |
| `iso27001` | `iso27001.json` |
| `soc2` | `soc2.json` |

Query parameters: none

Example response:

```json
{
  "framework": "CIS Microsoft Azure Foundations Benchmark",
  "version": "2.0.0",
  "total_controls": 20,
  "passed": 19,
  "failed": 1,
  "score_percent": 95,
  "controls": [
    {
      "rule_id": "AZ-STOR-001",
      "control_id": "3.5",
      "control_name": "Ensure that 'Public access level' is set to Private for blob containers",
      "status": "FAIL"
    }
  ]
}
```

Unknown framework response:

```json
{
  "error": "Unknown framework 'pci'",
  "supported": ["cis", "nist", "iso27001", "soc2"]
}
```

---

## GET /api/resources

Returns unique Azure resources derived from the most recent scan that has findings. Resources are aggregated from findings — one entry per distinct `resource_id`. Risk level is computed from the maximum severity finding on each resource.

Query parameters: none

Example response:

```json
{
  "summary": {
    "total": 12,
    "by_category": { "Storage": 3, "Network": 4, "Identity": 3, "Database": 2 },
    "by_risk_level": { "CRITICAL": 1, "HIGH": 3, "MEDIUM": 6, "LOW": 2, "INFO": 0, "NONE": 0 },
    "last_scan_at": "2026-06-03T15:12:51Z"
  },
  "resources": [
    {
      "resource_id": "/subscriptions/00000000/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/example",
      "resource_name": "example",
      "resource_type": "Microsoft.Storage/storageAccounts",
      "resource_group": "rg",
      "subscription_id": "00000000-0000-0000-0000-000000000000",
      "category": "Storage",
      "risk_level": "HIGH",
      "finding_count": 2
    }
  ]
}
```

No findings response (no scan with findings exists):

```json
{
  "summary": { "total": 0, "by_category": {}, "by_risk_level": {}, "last_scan_at": null },
  "resources": []
}
```

---

## GET /api/prioritization

Returns findings from the most recent scan grouped and ranked by risk score (`severity_weight × affected_resource_count`). Produces a matrix view, a ranked list, and recommended action items.

Query parameters: none

Example response:

```json
{
  "matrix": [
    {
      "id": "AZ-STOR-001",
      "ruleId": "AZ-STOR-001",
      "name": "Public Blob Access Enabled",
      "risk": "HIGH",
      "effort": 2,
      "category": "Storage",
      "severity": "HIGH",
      "affectedResources": 3,
      "resource": "storageAccount"
    }
  ],
  "rankings": [
    {
      "rank": 1,
      "ruleId": "AZ-STOR-001",
      "name": "Public Blob Access Enabled",
      "score": 30,
      "impact": "HIGH",
      "effort": 2,
      "category": "Storage",
      "resource": "storageAccount"
    }
  ],
  "action_items": [
    {
      "priority": 1,
      "ruleId": "AZ-STOR-001",
      "action": "Disable public blob access on all storage accounts",
      "impact": "HIGH",
      "effort": "LOW",
      "resources_affected": 3
    }
  ],
  "summary": {
    "total_issues": 8,
    "high_priority": 3,
    "total_affected_resources": 12
  }
}
```

---

## GET /api/drift

Compares the two most recent scans that have findings to surface configuration changes. Returns `ADDED` events (rule fired in latest scan but not the previous) and `REMOVED` events (rule fired in previous scan but not the latest). Returns an empty events list when fewer than two scans with findings exist.

Query parameters: none

Example response:

```json
{
  "summary": {
    "added": 2,
    "removed": 1,
    "modified": 0,
    "last_checked": "2026-06-03T15:12:51Z"
  },
  "events": [
    {
      "id": "AZ-NET-001-/subscriptions/00000000/.../nsg",
      "type": "ADDED",
      "rule_id": "AZ-NET-001",
      "rule_name": "SSH Access from Internet Not Restricted",
      "resource_id": "/subscriptions/00000000/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg",
      "resource_name": "nsg",
      "severity": "HIGH",
      "category": "Network",
      "detected_at": "2026-06-03T15:12:51Z"
    }
  ]
}
```

No drift response (fewer than two scans):

```json
{
  "summary": { "added": 0, "removed": 0, "modified": 0, "last_checked": null },
  "events": []
}
```

---

## GET /api/findings/&lt;id&gt;/playbook

Returns the structured remediation playbook for a specific finding. Loads the matching `playbooks/cli/fix_<rule>.sh` script and wraps the finding's remediation text as a portal step. Appends NVD links from any CVE references on the finding.

Path parameters: `id` — integer finding ID from `GET /api/findings`.

Example response:

```json
{
  "finding_id": 42,
  "rule_id": "AZ-STOR-001",
  "portal_steps": [
    "Navigate to Storage Accounts in the Azure Portal. Select the storage account. Under 'Configuration', set 'Allow Blob public access' to Disabled."
  ],
  "cli_commands": [
    "az storage account update --name <storage-account-name> --resource-group <rg> --allow-blob-public-access false"
  ],
  "validation_steps": [
    "Verify with: az storage account show --name <name> --query allowBlobPublicAccess"
  ],
  "references": [
    "https://nvd.nist.gov/vuln/detail/CVE-2021-XXXXX"
  ]
}
```

Not found response:

```json
{
  "error": "Finding 99 not found"
}
```

---

## Deferred endpoints

The following endpoints are called by the frontend but have no backend implementation yet. The frontend falls back to static mock data when these return 404.

| Endpoint | Used by | Status |
|---|---|---|
| `GET /api/monitoring` | Monitoring page — score trend chart, category distribution | Deferred. Score and findings data come from `GET /api/score` and `GET /api/findings` instead. |
