# Frontend/API Validation Guide

## 1. Scope

This guide validates the **frontend/API/database integration** of OpenShield. It covers:

- Frontend page inventory and routing
- API calls used by each page
- Live API mode setup
- JWT/auth token handling
- Backend endpoints expected by the frontend
- Loading, error, and empty state handling
- Known gaps and inconsistencies

**Out of scope:** Scanner rule validation (see `SCANNER_VALIDATION.md`) and Azure scenario testing (see `AZURE_SCENARIOS.md`).

---

## 2. Frontend Page Inventory

| Page/Component | Route | Purpose | API Calls | Loading State | Error State | Empty State | Notes/Gaps |
|---|---|---|---|---|---|---|---|
| Monitoring | `/monitoring` | Security score dashboard with trend, findings distribution, category breakdown | `api.getScore()`, `api.getFindings()`, `api.getScans()` | Skeleton cards + Loader | "Could not load monitoring data" message | Trend shows "available after multiple scans" | Only page (besides AI) with proper error handling |
| Discovery | `/discovery` | Azure resource inventory with filters | `api.getResources()`, `api.getFindings()`, `api.getPrioritization()` | `<Loader rows={8} />` | **None** — unhandled Promise.all rejection | Shows "0 of N shown" via filter logic | No `.catch()` — infinite spinner on API failure |
| DetailedScan | `/scan` | Finding detail with remediation playbook | `api.getFindings()`, `api.getPlaybook(id)` | `<Loader rows={6} />` | **None** — no `.catch()` on getFindings | Renders nothing if findings empty | Playbook shows "Loading playbook..." while fetching |
| Compliance | `/compliance` | Framework pass/fail (CIS, NIST, ISO, SOC2) | `api.getCompliance()` (fires 5 parallel requests internally) | `<Loader rows={8} />` | **None** — no `.catch()` | Empty controls table | Heaviest page load (5 concurrent API calls) |
| Drift | `/drift` | Configuration change timeline | `api.getDrift()` | `<Loader rows={6} />` | **None** — no `.catch()` | Empty timeline | No error feedback to user |
| Prioritization | `/prioritization` | Risk vs effort matrix, ranked findings | `api.getPrioritization()`, `api.getFindings()` | `<Loader rows={8} />` | **None** — unhandled Promise.all rejection | Empty matrix/rankings | No error feedback to user |
| AILayer | `/ai` | AI chat, executive summary, CVE analysis | `api.getFindings()`, `aiApi.getSummary()`, `aiApi.getCVEAnalysis()` | Per-section spinners | Findings: "Could not load findings" | "No findings yet. Run a scan first." | AI functions return null if no API key configured |

---

## 3. Page-to-API Endpoint Mapping

| Frontend Page | API Helper Function | Backend Endpoint | Method | Auth Required | Expected Data Source | Current Status | Validation Notes |
|---|---|---|---|---|---|---|---|
| All (health check) | `api.health()` | `GET /health` | GET | No | None (static response) | Registered in `app.py` | Always returns `{"status":"ok"}` |
| Monitoring | `api.getScore()` | `GET /api/score` | GET | No (public GET) | Computed from findings | Registered (`score_bp`) | Contract v1 score = 100 - (CRITICAL*20) - (HIGH*10) - (MEDIUM*5) - (LOW*2) |
| Monitoring | `api.getCVESummary()` | `GET /api/score/cve-summary` | GET | No (public GET) | DB + CVE correlation | Registered (`score_bp`) | Returns null on failure (try/catch) |
| Monitoring, Discovery, Scan, AI | `api.getFindings()` | `GET /api/findings` | GET | No (public GET) | Database (findings+rules) | Registered (`findings_bp`) | Supports ?severity, ?category, ?rule_id filters |
| DetailedScan | `api.getFinding(id)` | `GET /api/findings/:id` | GET | No (public GET) | Database | Registered (`findings_bp`) | Returns 404 if not found |
| DetailedScan | `api.getPlaybook(id)` | `GET /api/findings/:id/playbook` | GET | No (public GET) | Playbook files + DB | Registered (`findings_bp`) | Returns empty arrays on failure (graceful) |
| Monitoring | `api.getScans()` | `GET /api/scans` | GET | No (public GET) | Database (scans table) | Registered (`scans_bp`) | Ordered by most recent first |
| DetailedScan | `api.getScan(id)` | `GET /api/scans/:id` | GET | No (public GET) | Database | Registered (`scans_bp`) | Falls back to list search if direct lookup fails |
| Monitoring, Compliance | `api.triggerScan()` | `POST /api/scans/trigger` | POST | **Yes (JWT)** | Creates scan record | Registered (`scans_bp`) | Only POST endpoints require JWT |
| Compliance | `api.getComplianceCIS()` | `GET /api/compliance/cis` | GET | No (public GET) | Computed from findings+rules | Registered (`compliance_bp`) | Maps rule findings to CIS controls |
| Compliance | `api.getComplianceNIST()` | `GET /api/compliance/nist` | GET | No (public GET) | Computed from findings+rules | Registered (`compliance_bp`) | Maps rule findings to NIST controls |
| Compliance | `api.getComplianceISO27001()` | `GET /api/compliance/iso27001` | GET | No (public GET) | Computed from findings+rules | Registered (`compliance_bp`) | Maps rule findings to ISO controls |
| Compliance | `api.getComplianceSOC2()` | `GET /api/compliance/soc2` | GET | No (public GET) | Computed from findings+rules | Registered (`compliance_bp`) | Maps rule findings to SOC2 controls |
| Discovery | `api.getResources()` | `GET /api/resources` | GET | No (public GET) | Derived from findings | Registered (`resources_bp`) | Aggregates resources from latest scan |
| Prioritization | `api.getPrioritization()` | `GET /api/prioritization` | GET | No (public GET) | Computed from findings | Registered (`prioritization_bp`) | Returns matrix, rankings, action_items |
| Drift | `api.getDrift()` | `GET /api/drift` | GET | No (public GET) | Scan comparison | Registered (`drift_bp`) | Compares two most recent scans |
| AILayer | `aiApi.chat()` | `POST /api/ai/ask` | POST | **Yes (JWT)** | AI provider (RAG) | Registered (`ai_bp`) | Requires provider + api_key in body |
| AILayer | `aiApi.getSummary()` | `POST /api/ai/summary` | POST | **Yes (JWT)** | AI provider | Registered (`ai_bp`) | Requires provider + api_key in body |
| AILayer | `aiApi.getInsights()` | `POST /api/ai/insights` | POST | **Yes (JWT)** | AI provider | Registered (`ai_bp`) | Requires provider + api_key in body |
| AILayer | `aiApi.getPrioritisation()` | `POST /api/ai/prioritise` | POST | **Yes (JWT)** | AI provider | Registered (`ai_bp`) | Requires provider + api_key in body |

---

## 4. Live Mode Setup Requirements

### Environment Variables

| Variable | Where | Purpose | Example Value |
|---|---|---|---|
| `VITE_API_URL` | `frontend/.env.local` | Backend base URL | `http://localhost:5000` |
| `VITE_JWT_TOKEN` | `frontend/.env.local` | Pre-signed JWT for dev | `<signed-dev-jwt>` |
| `JWT_SECRET` | Backend env | HS256 signing key (min 32 chars in prod) | `<random-secret-min-32-chars>` |
| `DATABASE_URL` | Backend env | PostgreSQL connection string | `postgresql://user:pass@localhost:5432/openshield` |
| `ALLOWED_ORIGINS` | Backend env | CORS allowed origins (comma-separated) | `http://localhost:5173` |

### Token Handling

1. On mount, `App.jsx` checks for `VITE_JWT_TOKEN` in environment
2. If present, stores it in `localStorage` key `jwt_token` (overrides any stale value)
3. If absent and no existing token in localStorage, sets fallback `dev-local-token`
4. `api.js` reads `localStorage.getItem('jwt_token')` on every request
5. Token is sent as `Authorization: Bearer <token>` header on ALL requests (GET and POST)
6. Backend only validates token on non-GET, non-OPTIONS requests (GETs are public)

### Port Configuration

- Backend default: port **5000** (`app.py` line 241, overridable via `PORT` env var)
- Frontend dev server: port **5173** (Vite default)
- Frontend API_BASE fallback in dev: `http://localhost:5000`

### Important Notes

- Do NOT commit `.env.local` files
- `JWT_SECRET` must match the key used to sign `VITE_JWT_TOKEN`
- In production (`OPENSHIELD_ENV=production` or `RENDER=true`), the app refuses to start with a weak/missing JWT_SECRET
- CORS defaults to `*` if `ALLOWED_ORIGINS` not set (with a loud security warning)

---

## 5. Expected API Response Shapes

### Score (`GET /api/score`)

Raw backend response — source of truth: `api/models/finding.py` (`get_score()` is typed `-> int`). The endpoint returns a **bare integer** (0–100), not an object:
```json
68
```
> `normalizeScore()` in `frontend/src/utils/api.js` wraps the number into `{ "score": 68, "max_score": 100 }`. That object shape is frontend-only — the backend never emits `score`/`max_score` keys for this endpoint.

### Findings List (`GET /api/findings`)
```json
{
  "count": 25,
  "findings": [
    {
      "id": 1, "rule_id": "AZ-STOR-001", "rule_name": "...",
      "severity": "HIGH", "category": "Storage",
      "resource_id": "...", "resource_name": "...", "resource_type": "...",
      "description": "...", "remediation": "...", "detected_at": "..."
    }
  ]
}
```

### Scan List (`GET /api/scans`)

Raw backend response — source of truth: `api/models/finding.py` (`get_scans()` is typed `-> List[Dict]`). The endpoint returns a **bare array** of scan objects, not a wrapped object:
```json
[
  {
    "scan_id": "scan-001-20260529", "subscription_id": "...",
    "started_at": "...", "completed_at": "...",
    "total_findings": 25, "status": "completed"
  }
]
```
> `normalizeScans()` in `frontend/src/utils/api.js` wraps the array into `{ "count": N, "scans": [...] }`. The `count` field is frontend-only.

### Scan Trigger (`POST /api/scans/trigger`)

Returns `201 Created` on success (source of truth: `api/routes/scans.py`). The body is the full scan result; the representative subset below shows the most relevant fields:
```json
{
  "scan_id": "...", "subscription_id": "...",
  "started_at": "...", "completed_at": "...",
  "total_findings": 25, "status": "completed"
}
```

### Compliance Framework (`GET /api/compliance/cis`)
```json
{
  "framework": "CIS Microsoft Azure Foundations Benchmark",
  "version": "2.0.0", "score_percent": 74,
  "passed": 7, "failed": 6, "total_controls": 13,
  "controls": [
    { "control_id": "3.5", "control_name": "...", "rule_id": "AZ-STOR-001", "status": "FAIL" }
  ]
}
```

### Resources (`GET /api/resources`)

Raw backend response — source of truth: `api/routes/resources.py`:
```json
{
  "summary": {
    "total": 17, "by_category": {"Storage": 4, "Network": 4},
    "by_risk_level": {"HIGH": 7, "MEDIUM": 4}, "last_scan_at": "..."
  },
  "resources": [
    {
      "id": "/subscriptions/.../storageAccounts/example",
      "name": "example",
      "type": "Microsoft.Storage/storageAccounts",
      "category": "Storage",
      "resource_group": "rg-prod",
      "subscription_id": "00000000-0000-0000-0000-000000000000",
      "location": "",
      "risk": "HIGH",
      "discovered_at": "2026-05-09T12:00:00+00:00",
      "config": {}
    }
  ]
}
```
> Notes: the backend does **not** return `finding_count`, and the risk field is named `risk` (not `risk_level`). `location` and `config` are currently always emitted as `""`/`{}` by the backend.

#### Frontend-normalized resources shape

`normalizeResource()` in `frontend/src/utils/api.js` remaps the raw backend response into camelCase props for components. These field names come from the **frontend layer, not the backend**:
```json
{
  "id": "...", "name": "...", "type": "...", "category": "Storage",
  "resourceGroup": "rg-prod", "subscription": "...", "location": "",
  "risk": "HIGH", "findingCount": 0, "discoveredAt": "...", "config": {}
}
```
> `findingCount` is a frontend-only field: it maps from `finding_count`, which the backend never sends, so it defaults to `0`. `risk` is read as `risk_level || risk`; the backend supplies `risk`. `subscription` maps from the backend's `subscription_id`.

### Prioritization (`GET /api/prioritization`)

Raw backend response — source of truth: `api/routes/prioritization.py`. Note that
the `matrix`/`rankings`/`action_items` entries use snake_case (`rule_id`,
`affected_resources`), while the `summary` object uses camelCase keys exactly as
the backend emits them:
```json
{
  "matrix": [
    { "id": 1, "rule_id": "AZ-STOR-001", "name": "...", "risk": 8, "effort": 1,
      "category": "Storage", "severity": "HIGH", "affected_resources": 3, "resource": "..." }
  ],
  "rankings": [
    { "rank": 1, "rule_id": "AZ-STOR-001", "name": "...", "score": 30, "severity": "HIGH",
      "category": "Storage", "effort": 1, "impact": "HIGH", "resource": "..." }
  ],
  "action_items": [
    { "id": 1, "action": "...", "impact": "HIGH", "effort": "LOW", "eta": "15 mins",
      "rule_id": "AZ-STOR-001", "resource": "..." }
  ],
  "summary": {
    "totalFindings": 25, "criticalFindings": 7, "highRiskFindings": 7,
    "mediumRiskFindings": 4, "lowRiskFindings": 2, "recommendedActionsCount": 10,
    "estimatedFixTime": "8 hours", "topPriority": "Public Blob Access Enabled"
  }
}
```

#### Frontend-normalized prioritization shape

`normalizePrioritizationResponse()` in `frontend/src/utils/api.js` converts the
`matrix`, `rankings`, and `action_items` entries to camelCase (`ruleId`,
`affectedResources`) and exposes `action_items` as `actionItems`. The `summary`
object is passed through unchanged because it is already camelCase from the backend.
These camelCase entry field names are frontend-only — do not expect them in the raw
backend response above.

### Drift (`GET /api/drift`)

Raw backend response — source of truth: `api/routes/drift.py`. Each event uses change-oriented fields (`rule_violated`, `field`, `old_value`, `new_value`, `changed_by`, `changed_at`) — **not** `rule_id`/`rule_name`/`detected_at`. The `summary` also includes `total`:
```json
{
  "summary": { "total": 3, "added": 2, "removed": 1, "modified": 0, "last_checked": "..." },
  "events": [
    {
      "id": 1, "type": "ADDED", "severity": "HIGH",
      "resource_name": "...", "resource_type": "...", "resource_group": "rg-prod",
      "field": "security_policy", "old_value": null, "new_value": "HIGH",
      "changed_by": "azure-policy-scan", "changed_at": "...", "rule_violated": "AZ-NET-001"
    }
  ]
}
```
> `type` is `"ADDED"` or `"REMOVED"`; `modified` is always `0` in the current implementation. `normalizeDriftEvent()` in `frontend/src/utils/api.js` maps these to camelCase (`ruleViolated`, `changedAt`, `oldValue`, `newValue`, …), reading both the backend names and camelCase fallbacks.

### Finding Playbook (`GET /api/findings/:id/playbook`)

Raw backend response — source of truth: `api/routes/findings.py` (`get_playbook`). The endpoint returns **only** the four playbook content fields; it does **not** echo `finding_id` or `rule_id` (those belong to the parent finding from `GET /api/findings/:id`):
```json
{
  "portal_steps": ["Step 1...", "Step 2..."],
  "cli_commands": ["az network nsg rule delete ..."],
  "validation_steps": ["Run: az network nsg rule list ..."],
  "references": ["https://learn.microsoft.com/en-us/azure/security/"]
}
```

### AI Responses (`POST /api/ai/ask`)

`sources` is a list of source strings (RAG document identifiers from the retriever), not objects. Source of truth: `api/routes/ai.py`:
```json
{
  "answer": "...",
  "sources": ["RULES.md", "AZ-NET-001.md"],
  "provider": "anthropic",
  "model": "claude-..."
}
```
> `model` echoes the optional `model` field from the request body and is `null` when the caller does not supply one.

### AI Summary (`POST /api/ai/summary`)

Returns `summary`, `sources`, `provider`, and `model`. Source of truth: `api/routes/ai.py`:
```json
{
  "summary": "...",
  "sources": ["RULES.md", "AZ-STOR-001.md"],
  "provider": "anthropic",
  "model": "claude-..."
}
```

---

## 6. Auth/JWT Validation Checklist

| # | Check | Expected Behaviour | Notes |
|---|---|---|---|
| 1 | `GET /health` without JWT | Returns `{"status":"ok"}` 200 | Always public |
| 2 | `GET /api/findings` without JWT | Returns 200 with findings | **All GET routes are public** — `_is_public_get()` in `app.py` returns True for any path starting with `/api/` |
| 3 | `POST /api/scans/trigger` without JWT | Returns 401 `{"error":"Missing or malformed Authorization header"}` | POST endpoints require JWT |
| 4 | `POST /api/ai/ask` with invalid JWT | Returns 401 `{"error":"Invalid token: ..."}` | JWT validated via PyJWT HS256 |
| 5 | `POST /api/scans/trigger` with valid JWT | Returns 201 with scan result | Token decoded, `g.user` set from payload |
| 6 | Frontend sends Authorization header when `jwt_token` exists in localStorage | Yes — `api.js` line 20-21 attaches Bearer header on all requests | Sent on GETs too (harmless, just unnecessary) |
| 7 | Frontend behaviour when `jwt_token` missing from localStorage | Sends request without Authorization header | GETs still work (public); POSTs will get 401 |
| 8 | Frontend behaviour when token is expired/invalid | `apiFetch` throws `Error("API 401 Unauthorized")` | Most pages show infinite spinner (no error handling) — only Monitoring shows error message |
| 9 | Token with expired signature | Backend returns 401 `{"error":"Token has expired"}` | `jwt.ExpiredSignatureError` caught specifically |

### Important: Auth Model Documentation Mismatch

| Source | Claim | Accuracy |
|---|---|---|
| `api/app.py` (actual code) | All GETs public, only POSTs need JWT | **Authoritative — this is the runtime behaviour** |
| `docs/api-reference.md` | "All GET requests are public" | Correct |
| `frontend/API_ENDPOINTS.txt` | Shows "Authorization: Bearer" on GET endpoints | **Outdated/incorrect** |

---

## 7. CORS/Error Handling Checklist

| # | Check | Expected Behaviour | Status |
|---|---|---|---|
| 1 | OPTIONS/preflight does not fail | Flask-CORS handles preflight automatically | OK — CORS configured for all origins by default |
| 2 | API errors are visible to user (Monitoring) | Shows "Could not load monitoring data" | OK |
| 3 | API errors are visible to user (other pages) | Should show error message | **GAP** — 5 pages show infinite loader |
| 4 | Backend 401 does not silently render fake data | Frontend throws on non-ok response, no mock fallback | OK — `api.js` line 23: `if (!res.ok) throw` |
| 5 | Backend 500 shows clear frontend failure state | Only Monitoring catches and displays | **GAP** — other pages hang |
| 6 | Empty findings renders appropriate state | AILayer: "No findings yet. Run a scan first." | Partial — only AILayer handles this explicitly |
| 7 | Empty scans renders no-history state | Monitoring trend: "available after multiple scans" | OK |
| 8 | Missing/unreachable backend does not crash app | App renders but pages show loader indefinitely | **GAP** — no timeout or retry logic on most pages |
| 9 | CORS origin mismatch returns clear error | Browser blocks request, console shows CORS error | Frontend does not surface CORS errors distinctly |

---

## 8. Build/Lint/Test Results

See `TEST_RESULTS.md` for detailed command output. Summary:

| Command | Status | Notes |
|---|---|---|
| `npm install` | Pass | 243 packages, 0 vulnerabilities |
| `npm run lint` | Fail (65 errors, 4 warnings) | Mostly unused `React` imports (cosmetic, React 19 doesn't require explicit import) |
| `npm run build` | Pass | Built in 3.53s, 782 KB JS bundle |
| `npm run dev` | Pass | Vite v8.0.14, starts on `http://localhost:5173` in 697ms |
| `pytest` | Fail (collection error) | `DATABASE_URL` env var not set — cannot connect to PostgreSQL |

---

## 9. Known Frontend/API Gaps

### 9.1 Documentation Inconsistencies

| Issue | Details | Impact |
|---|---|---|
| Auth model mismatch | `API_ENDPOINTS.txt` claims GETs need auth; actual code (`app.py`) makes all GETs public | Misleads developers into thinking JWT is required for read operations |
| Port inconsistency | `API_ENDPOINTS.txt` says port 5001; `api.js` and `app.py` use port 5000 | Could cause connection failures if developer follows wrong docs |
| Stale "Demo Mode" docs | `API_ENDPOINTS.txt` describes Demo/Live toggle with mock JSON files; this feature no longer exists in code | Confuses developers looking for mock mode |
| Stale "DEFERRED" list | `API_ENDPOINTS.txt` lists resources, drift, prioritization, playbook as "not built yet"; all are implemented and registered | Developers may skip using these endpoints thinking they don't work |
| AI endpoint path errors | `API_ENDPOINTS.txt` says `POST /api/ai/chat` (actual: `/api/ai/ask`), `GET /api/ai/summary` (actual: `POST /api/ai/summary`), `GET /api/ai/cve-analysis` (actual: `GET /api/score/cve-summary`) | Frontend would call wrong endpoints if built from these docs |

### 9.2 Missing Error Handling

| Page | Issue |
|---|---|
| Discovery | No `.catch()` on `Promise.all` — infinite spinner on failure |
| Prioritization | No `.catch()` on `Promise.all` — infinite spinner on failure |
| DetailedScan | No `.catch()` on `api.getFindings()` — infinite spinner on failure |
| Compliance | No `.catch()` on `api.getCompliance()` — infinite spinner on failure |
| Drift | No `.catch()` on `api.getDrift()` — infinite spinner on failure |

### 9.3 Lint Issues

- 65 ESLint errors: primarily unused `React` imports (unnecessary in React 19 with automatic JSX runtime) and a few unused variables
- 4 warnings: missing dependency arrays in useEffect hooks
- Does not block build (Vite ignores ESLint errors)

### 9.4 Backend Test Gap

- `pytest` cannot run without `DATABASE_URL` environment variable
- Tests require a PostgreSQL instance to be available
- No documented dev database setup instructions in repo

---

## 10. Recommended Follow-up Issues

1. **Update `frontend/API_ENDPOINTS.txt`** — Fix auth model description (GETs are public), correct port to 5000, remove stale Demo Mode section, update AI endpoint paths, mark deferred endpoints as implemented.

2. **Add frontend error states to 5 pages** — Discovery, Prioritization, DetailedScan, Compliance, and Drift need `.catch()` handlers with user-visible error messages (follow the pattern established in Monitoring).

3. **Fix ESLint errors** — Remove unnecessary `React` imports across all components (React 19 automatic JSX runtime doesn't need them). Fix unused variables in `AILayer.jsx`, `DriftEventCard.jsx`, `RiskRanking.jsx`, `ActionItems.jsx`.

4. **Add lightweight contract tests** — Create integration tests that validate `/health`, JWT auth flow, and a few key endpoints (`/api/findings`, `/api/score`, `/api/scans`) against the expected response shapes.

5. **Document dev database setup** — Add instructions for setting up a local PostgreSQL instance, running migrations, and seeding test data so `pytest` can run locally.

6. **Add request timeout/retry on frontend** — Consider adding a timeout and retry mechanism (or at minimum a timeout that triggers the error state) so pages don't hang indefinitely when the backend is slow or unreachable.

7. **Align `docs/api-reference.md` response shapes** — The backend (`api/routes/resources.py`) returns the risk field as `risk` (confirmed), while `api.js` reads it defensively as `risk_level || risk`. If `api-reference.md` documents `risk_level` for the `resources` endpoint, update it to `risk` to match the backend.
