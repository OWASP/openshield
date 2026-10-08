# Deprecated Render deployment guide

This guide describes the previous single-service deployment architecture and is no
longer current.

OpenShield now deploys the API and scan worker as separate Render services through
the deterministic manual workflow documented here:

- [Current Render deployment guide](deployment/render.md)
- [Render Blueprint](../render.yaml)
- [Deployment workflow](../.github/workflows/deploy.yml)

Do not use the instructions previously contained in this document.
---

## 2. Methodology and Test Rationale

To ensure the highest reliability of the deployment while remaining community-friendly, specific methods and test strategies were chosen:

### 2.1 Infrastructure and Pipeline Strategy
* **Targeting Render over Azure F1:** Azure App Service's F1 tier imposes a strict 60 CPU-minute daily cap. Render provides unmetered CPU and always-on availability on paid instances, making it significantly more reliable for production environments.
* **Database Migrations:** `startup.sh` runs `alembic upgrade head` before starting the worker and Gunicorn. Existing production databases must complete the documented one-time `alembic stamp head` step before this release is deployed.
* **Pre-commit Hook:** Fails fast. By running syntax checks and local API smoke tests *before* the commit is allowed, we prevent broken code from polluting the remote branch.
* **Community-Friendly CI Gate:** The GitHub Action is designed to be zero-friction for contributors.
    * **Optional Smoke Tests:** If `JWT_SECRET` is not set (typical for forks), the smoke test step is gracefully skipped rather than failing the build.
    * **Configurable URL:** The `API_URL` is configurable via GitHub Secrets/Variables, defaulting to the main production instance if not provided.
    * **Conditional Real Scan Tests:** TC-13 and TC-14 (real Azure scan execution) only run when `RUN_REAL_SCAN=true` and all four Azure credentials are present. This separates API smoke testing from live scan regression testing. Contributor and fork CI always passes safely — real scan validation is reserved for maintainer-controlled deployment pipelines (`dev` and `main` branches).

### 2.2 Token Generation Method
* **Dynamic HS256 Signing:** Instead of using a hardcoded dummy string, the test script dynamically generates a real token signed with the environment's `JWT_SECRET`.
* **Explicit `JWT_SECRET` Required:** The smoke test no longer falls back to the insecure default. `JWT_SECRET` must be set explicitly before running the script, whether locally or in CI.

> [!CAUTION]
> **PRODUCTION FAIL-CLOSED:** The API refuses to start in production (`OPENSHIELD_ENV=production` or `RENDER=true`) if `JWT_SECRET` is missing, equals the known default `change-me-in-production`, or is shorter than 32 characters. Generate a strong secret with:
> ```
> python -c "import secrets; print(secrets.token_urlsafe(32))"
> ```
> Local development runs (no production signal set) are allowed to use the default and will log a loud warning.

### 2.3 API Smoke Test Strategy (The 32 Cases)
The 32 test cases prove the API is structurally sound, contract-correct, and resilient:
* **Health (TC-01 to TC-03):** Confirms base connectivity and that `/health` is public.
* **Findings (TC-04 to TC-08):** Verifies shape, filtering, and bad-input handling.
* **Score (TC-09 to TC-11):** Confirms numeric result bounded 0–100.
* **Scans (TC-12 to TC-14):** List endpoint always runs; real scan trigger is maintainer-gated.
* **Compliance (TC-15 to TC-18):** All four frameworks — CIS, NIST, ISO 27001, SOC 2.
* **Auth/Security (TC-19 to TC-20):** POST endpoints reject missing and malformed JWTs. All GET endpoints are intentionally public.
* **Dashboard Contract (TC-21 to TC-28):** Validates the four v0.2.0 endpoints — `/api/resources`, `/api/prioritization`, `/api/drift`, `/api/findings/<id>/playbook` — against their documented response shapes.
* **Edge Cases (TC-29 to TC-32):** 404 routing, empty body, bad query param, Content-Type.

#### Conditional vs Always-Run Tests

| Mode | TC-13 / TC-14 | All others |
|---|---|---|
| Contributor / fork (no `RUN_REAL_SCAN`) | `SKIP` — printed with reason, not a failure | Always run |
| Maintainer deployment (`RUN_REAL_SCAN=true` + Azure credentials) | Run real scan against live subscription | Always run |

TC-27 and TC-28 (playbook) are automatically skipped with a clear reason if the database has no findings. Seed the database first with `seed_render_db.py` to enable them.

Run modes:
```bash
# Contributor / local (no Azure credentials needed)
API_URL=https://openshield-api.onrender.com JWT_SECRET=<secret> python tests/smoke_test.py

# Maintainer — full real scan
API_URL=https://openshield-api.onrender.com JWT_SECRET=<secret> \
  RUN_REAL_SCAN=true \
  AZURE_SUBSCRIPTION_ID=<sub-id> \
  AZURE_CLIENT_ID=<client-id> \
  AZURE_CLIENT_SECRET=<secret> \
  AZURE_TENANT_ID=<tenant-id> \
  python tests/smoke_test.py
```

---

## 3. Files Under Test

| File | Purpose |
|---|---|
| `startup.sh` | Runs Alembic once, then starts the worker and Gunicorn |
| `alembic/` | Versioned PostgreSQL schema migrations |
| `.github/workflows/deploy.yml` | Flexible GitHub Actions workflow (optional smoke tests) |
| `tests/smoke_test.py` | 23-case functional test suite with default secret support |
| `.git/hooks/pre-commit` | Local Git hook enforcing syntax checks and local smoke tests |
| `requirements.txt` | Pinned runtime dependencies — see dependency notes below |

### 3.1 Dependency Notes

| Package | Status | Reason |
|---|---|---|
| `msrest==0.7.1` | Kept (explicit pin) | Transitive dependency of `azure-mgmt-rdbms`, `azure-mgmt-sql`, and `azure-mgmt-storage`. These SDK packages have not fully migrated to `azure-core`. Without an explicit pin, Render's clean pip install can resolve a mismatched version and break scan execution. |

---

## 4. Test Environment Setup

### 4.1 Prerequisites
- Python 3.11 installed locally.
- Render account (render.com).
- OpenShield repository cloned locally.
- `.env` file populated locally with a valid `JWT_SECRET` and `DATABASE_URL`.
- Pre-commit hook installed locally (`chmod +x .git/hooks/pre-commit`).

### 4.2 Create Test Resources in Render
1.  **Render PostgreSQL Database (Free Tier)**
    - Name: `openshield-db`
2.  **Render Web Service (Starter instance or higher)**
    - Connected to your branch.
    - Start Command: `./startup.sh`
    - Environment Variables set: `DATABASE_URL`, `JWT_SECRET`, `ALLOWED_ORIGINS`, `AZURE_SUBSCRIPTION_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`.

### 4.3 Configure GitHub Secrets
To enable the automated smoke tests in the CI/CD pipeline, you **must** add the following secrets to your GitHub repository (**Settings > Secrets and variables > Actions**):

| Secret Name | Required for | Purpose |
|---|---|---|
| `JWT_SECRET` | All smoke tests | Must match the value set in Render. Used to sign tokens for test requests. |
| `API_URL` | All smoke tests (optional) | Your Render Service URL. Defaults to the main production instance if not set. |
| `AZURE_SUBSCRIPTION_ID` | Real scan tests | Azure Subscription ID passed to the scan trigger endpoint, and to the `azure/login` OIDC step. |
| `AZURE_CLIENT_ID` | Real scan tests | Service principal client ID for `DefaultAzureCredential` and the `azure/login` OIDC step. |
| `AZURE_TENANT_ID` | Real scan tests | Azure AD tenant ID for `DefaultAzureCredential` and the `azure/login` OIDC step. |

> **Note:** `RUN_REAL_SCAN=true` is set automatically by `deploy.yml` on `dev` and `main` branches. Forks and contributor PRs never set this flag, so TC-13 and TC-14 are always skipped in fork CI regardless of which secrets are present.
>
> As of #160, Azure authentication for real-scan smoke tests uses GitHub OIDC federation
> instead of a stored client secret. See `docs/ci-oidc-setup.md` for the one-time setup.

---

## 5. Test Cases

### Part 1: Deployment & Pipeline Infrastructure

**DP-01 — Pre-commit hook enforces checks**
* **Steps:** Modify a file and run `git commit` with the local API turned off, then with it turned on.
* **Expected:** Blocks/warns when API is off; runs the 23-test suite and passes when API is on.

**DP-02 — Render executes startup script successfully**
* **Steps:** Push code to GitHub and monitor Render deployment logs.
* **Expected:** Logs show Alembic upgrading to `head` before the worker and Gunicorn start.

**DP-03 — GitHub Actions CI pipeline passes**
* **Steps:** Push a commit and monitor the GitHub Actions tab.
* **Expected:**
    * **Maintainer repo (`dev`/`main`):** Runs 21 always-on tests + TC-13/TC-14 real scan with `RUN_REAL_SCAN=true`. All 23 pass.
    * **Contributor / fork:** TC-13 and TC-14 show as `SKIP` with a clear reason. 21/21 non-scan tests pass. Workflow exits green.

---

### Part 2: API Smoke Tests (Executed via `smoke_test.py`)

Run the following command against the live URL to execute these tests (contributor mode — TC-13/TC-14 skipped):
```bash
API_URL=https://openshield-api.onrender.com JWT_SECRET=<secret> python tests/smoke_test.py
```

To run the full 23-case suite including real scan tests (maintainer only):
```bash
API_URL=https://openshield-api.onrender.com JWT_SECRET=<secret> \
  RUN_REAL_SCAN=true \
  AZURE_SUBSCRIPTION_ID=<sub-id> AZURE_CLIENT_ID=<id> \
  AZURE_CLIENT_SECRET=<secret> AZURE_TENANT_ID=<tenant> \
  python tests/smoke_test.py
```

#### Health Check
* **TC-01:** GET `/health` returns HTTP 200.
* **TC-02:** GET `/health` returns JSON `{"status": "ok"}`.
* **TC-03:** GET `/health` requires no auth token (public route).

#### Findings Endpoint
* **TC-04:** GET `/api/findings` returns HTTP 200.
* **TC-05:** GET `/api/findings` returns a `findings` key in JSON.
* **TC-06:** GET `/api/findings` returns a numeric `count` key.
* **TC-07:** GET `/api/findings?severity=HIGH` correctly filters results.
* **TC-08:** GET `/api/findings?severity=INVALID` handles bad input safely (returns 200 or 400).

#### Score Endpoint
* **TC-09:** GET `/api/score` returns HTTP 200.
* **TC-10:** GET `/api/score` returns a numeric score when `status` is `"OK"` (a numeric score is not required when `status` is `"NO_SCAN_DATA"` — `score` is legitimately `null` then).
* **TC-11:** GET `/api/score` ensures the score is mathematically between 0 and 100, or `null` with a non-`"OK"` status.

#### Scans Endpoint
* **TC-12:** GET `/api/scans` returns HTTP 200.
* **TC-13:** *(Conditional — requires `RUN_REAL_SCAN=true` and Azure credentials)* POST `/api/scans/trigger` returns HTTP 200, 201, or 202. Skipped in contributor/fork CI.
* **TC-14:** *(Conditional — requires `RUN_REAL_SCAN=true` and Azure credentials)* POST `/api/scans/trigger` returns a `scan_id` or `job_id`. Skipped in contributor/fork CI.

#### Compliance Endpoints
* **TC-15:** GET `/api/compliance/cis` returns HTTP 200.
* **TC-16:** GET `/api/compliance/nist` returns HTTP 200.
* **TC-17:** GET `/api/compliance/iso27001` returns HTTP 200.

#### Compliance Endpoints (continued)
* **TC-18:** GET `/api/compliance/soc2` returns HTTP 200.

#### Auth & Security Edge Cases
* **TC-19:** POST `/api/scans/trigger` without any auth header returns HTTP 401.
* **TC-20:** POST `/api/scans/trigger` with a malformed JWT returns HTTP 401.

> **Note:** All `GET /api/*` routes are public — no token required. Auth is enforced only on `POST` endpoints (`/api/scans/trigger`, `/api/ai/*`).

#### General Edge Cases
* **TC-21:** GET `/nonexistent-endpoint-xyz` returns HTTP 404.
* **TC-22:** POST `/api/scans/trigger` with an empty JSON body returns HTTP 400 (missing `subscription_id`) without crashing.
* **TC-23:** GET `/api/findings?limit=0` does not crash the server.
* **TC-24:** All valid endpoint responses include the `application/json` Content-Type.

---

## 6. Cleanup

To clean up, delete both the Web Service and the PostgreSQL database from the Render dashboard Settings page. Note: free-tier PostgreSQL databases are automatically deleted by Render after 90 days; paid instances do not have this limit.

---

## 7. Pass / Fail Summary Table

| Test Case | Description | Expected | Status |
|---|---|---|---|
| **DP-01** | Pre-commit Git hook functioning | Hook runs & enforces rules | [ ] |
| **DP-02** | Render deployment & startup | App goes Live & DB inits | [ ] |
| **DP-03** | GitHub Actions CI Pipeline | Workflow passes (Green) | [ ] |
| **TC-01** | `/health` returns 200 | Pass | [ ] |
| **TC-02** | `/health` returns status ok | Pass | [ ] |
| **TC-03** | `/health` requires no auth | Pass | [ ] |
| **TC-04** | `/api/findings` returns 200 | Pass | [ ] |
| **TC-05** | `/api/findings` returns findings key | Pass | [ ] |
| **TC-06** | `/api/findings` returns count key | Pass | [ ] |
| **TC-07** | `/api/findings` severity filter | Pass | [ ] |
| **TC-08** | `/api/findings` invalid severity | Pass | [ ] |
| **TC-09** | `/api/score` returns 200 | Pass | [ ] |
| **TC-10** | `/api/score` returns numeric | Pass | [ ] |
| **TC-11** | `/api/score` bounded 0-100 | Pass | [ ] |
| **TC-12** | `/api/scans` returns 200 | Pass | [ ] |
| **TC-13** | `/api/scans/trigger` works | 200/201/202 (Skip in fork CI) | [ ] |
| **TC-14** | `/api/scans/trigger` returns ID | Pass (Skip in fork CI) | [ ] |
| **TC-15** | `/api/compliance/cis` works | Pass | [ ] |
| **TC-16** | `/api/compliance/nist` works | Pass | [ ] |
| **TC-17** | `/api/compliance/iso27001` works | Pass | [ ] |
| **TC-18** | `/api/compliance/soc2` works | Pass | [ ] |
| **TC-19** | POST trigger without auth returns 401 | Pass | [ ] |
| **TC-20** | POST trigger bad token returns 401 | Pass | [ ] |
| **TC-21** | `/api/resources` returns 200 | Pass | [ ] |
| **TC-22** | `/api/resources` returns correct shape | Pass | [ ] |
| **TC-23** | `/api/prioritization` returns 200 | Pass | [ ] |
| **TC-24** | `/api/prioritization` returns correct shape | Pass | [ ] |
| **TC-25** | `/api/drift` returns 200 | Pass | [ ] |
| **TC-26** | `/api/drift` returns correct shape | Pass | [ ] |
| **TC-27** | `/api/findings/<id>/playbook` returns 200 | Pass (skip if DB empty) | [ ] |
| **TC-28** | `/api/findings/<id>/playbook` returns correct shape | Pass (skip if DB empty) | [ ] |
| **TC-29** | 404 routing works safely | Pass | [ ] |
| **TC-30** | Empty body payload handled | Pass (400) | [ ] |
| **TC-31** | Limit=0 query handled safely | Pass | [ ] |
| **TC-32** | Content-Type is JSON | Pass | [ ] |

**Maintainer repo:** All 35 checks (3 Pipeline + 32 API) must pass before merging to `dev` or `main`.
**Fork / contributor:** 33 checks (3 Pipeline + 30 API) must pass; TC-13 and TC-14 are expected `SKIP`.
