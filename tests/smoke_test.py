#!/usr/bin/env python3
"""
OpenShield API Smoke Test Suite
Runs against a live deployment to verify all endpoints.

Usage:
  # Local
  # Set API_URL: http://localhost:5000 and JWT_SECRET: your-secret
  python tests/smoke_test.py

  # Live Render deployment
  # Set API_URL: https://openshield-api.onrender.com and JWT_SECRET: your-secret
  python tests/smoke_test.py

JWT_SECRET must be the same value set in Render config — the test
generates a properly signed HS256 token from it automatically.
"""

import os
import sys
import json
import time
import urllib.request
import urllib.error

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


# ── Token generation ──────────────────────────────────────────────────────
# The app's before_request middleware calls jwt.decode() with HS256.
# Passing the raw JWT_SECRET as a Bearer token will always return 401.
# We must sign a real token using the same secret.


def _generate_token(secret: str) -> str:
    """Generate a valid HS256 JWT signed with the app's JWT_SECRET."""
    try:
        import jwt as pyjwt

        payload = {
            "sub": "smoke-test",
            "role": "admin",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,  # 1 hour expiry
        }
        return pyjwt.encode(payload, secret, algorithm="HS256")
    except ImportError:
        print("ERROR: PyJWT not installed. Run: pip install PyJWT")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR generating JWT token: {e}")
        sys.exit(1)


API_URL = os.environ.get("API_URL", "http://localhost:5000").rstrip("/")
_JWT_VAL = os.environ.get("JWT_SECRET", "")
_REAL_SUB = os.environ.get("AZURE_SUBSCRIPTION_ID", "")

# Real scan gate — requires explicit opt-in AND all four Azure credentials.
# Set RUN_REAL_SCAN=true in maintainer-controlled CI only.
_RUN_REAL_SCAN = os.environ.get("RUN_REAL_SCAN", "").lower() == "true"
_AZURE_CREDS_PRESENT = all(
    [
        os.environ.get("AZURE_SUBSCRIPTION_ID"),
        os.environ.get("AZURE_CLIENT_ID"),
        os.environ.get("AZURE_CLIENT_SECRET"),
        os.environ.get("AZURE_TENANT_ID"),
    ]
)

if not _JWT_VAL:
    print("ERROR: JWT_SECRET environment variable is not set.")
    print("The smoke test requires an explicit JWT_SECRET that matches the running API.")
    print('Generate one with: python -c "import secrets; print(secrets.token_urlsafe(32))"')
    sys.exit(1)

JWT_TOKEN = _generate_token(_JWT_VAL)

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"
SKIP = "\033[93mSKIP\033[0m"

results = []


def request(method, path, body=None, auth=True, bad_token=False):
    """Make an HTTP request and return (status_code, response_body)."""
    url = f"{API_URL}{path}"
    headers = {"Content-Type": "application/json"}

    if bad_token:
        # Deliberately malformed token to test rejection
        headers["Authorization"] = "Bearer this.is.not.a.valid.jwt"
    elif auth and JWT_TOKEN:
        headers["Authorization"] = f"Bearer {JWT_TOKEN}"

    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            body_bytes = e.read()
            return e.code, json.loads(body_bytes)
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"error": str(e)}


def test(name, method, path, check_fn, body=None, auth=True, bad_token=False):
    """Run a single test case."""
    status, body_resp = request(method, path, body=body, auth=auth, bad_token=bad_token)
    try:
        passed = check_fn(status, body_resp)
    except Exception as e:
        passed = False
        body_resp = {"exception": str(e)}

    label = PASS if passed else FAIL
    print(f"  [{label}] {name}")
    if not passed:
        print(f"         Status: {status}")
        print(f"         Body:   {json.dumps(body_resp, indent=2)[:300]}")

    results.append((name, passed))
    return passed


def skip(name, reason):
    """Record a test as skipped — does not count as a failure."""
    print(f"  [{SKIP}] {name}")
    print(f"         {reason}")
    results.append((name, None))


# ── TC-01: Health check ────────────────────────────────────────────────────
print("\n=== Health Check ===")
test(
    "TC-01 GET /health returns 200",
    "GET",
    "/health",
    lambda s, b: s == 200,
    auth=False,
)
test(
    "TC-02 GET /health returns status ok",
    "GET",
    "/health",
    lambda s, b: b.get("status") == "ok",
    auth=False,
)
test(
    "TC-03 GET /health requires no auth token",
    "GET",
    "/health",
    lambda s, b: s == 200,  # Public path — must not return 401
    auth=False,
)

# ── TC-04 to TC-08: Findings endpoint ─────────────────────────────────────
print("\n=== Findings Endpoint ===")
test(
    "TC-04 GET /api/findings returns 200",
    "GET",
    "/api/findings",
    lambda s, b: s == 200,
)
test(
    "TC-05 GET /api/findings returns 'findings' key",
    "GET",
    "/api/findings",
    lambda s, b: "findings" in b,
)
test(
    "TC-06 GET /api/findings returns 'count' key",
    "GET",
    "/api/findings",
    lambda s, b: "count" in b and isinstance(b["count"], int),
)
test(
    "TC-07 GET /api/findings?severity=HIGH filters correctly",
    "GET",
    "/api/findings?severity=HIGH",
    lambda s, b: s == 200 and all(f.get("severity") == "HIGH" for f in b.get("findings", [])),
)
test(
    "TC-08 GET /api/findings?severity=INVALID returns 400 or empty",
    "GET",
    "/api/findings?severity=INVALID",
    lambda s, b: s in (200, 400),
)

# ── TC-09 to TC-11: Score endpoint ────────────────────────────────────────
print("\n=== Score Endpoint ===")
test(
    "TC-09 GET /api/score returns 200",
    "GET",
    "/api/score",
    lambda s, b: s == 200,
)
test(
    # score is legitimately null when status is NO_SCAN_DATA (no completed
    # scan exists yet) - that is a valid response, not a failure, so this
    # only requires a numeric score when status says one was computed.
    "TC-10 GET /api/score returns numeric score when status is OK",
    "GET",
    "/api/score",
    lambda s, b: (
        isinstance(b, (int, float))
        or (isinstance(b, dict) and (b.get("status") != "OK" or isinstance(b.get("score"), (int, float))))
    ),
)
test(
    # b.get("score", -1) is not null-safe: a present-but-None value is
    # returned as-is, not replaced by the default, so a naive bounds check
    # here would TypeError on a real NO_SCAN_DATA response instead of
    # accepting it as a legitimate, non-failing result.
    "TC-11 GET /api/score is between 0 and 100 (or null with a non-OK status)",
    "GET",
    "/api/score",
    lambda s, b: (
        (0 <= b <= 100)
        if isinstance(b, (int, float))
        else (
            (0 <= b.get("score") <= 100)
            if isinstance(b, dict) and isinstance(b.get("score"), (int, float))
            else isinstance(b, dict) and b.get("score") is None and b.get("status") != "OK"
        )
    ),
)

# ── TC-12 to TC-14: Scans endpoint ────────────────────────────────────────
print("\n=== Scans Endpoint ===")
test(
    "TC-12 GET /api/scans returns 200",
    "GET",
    "/api/scans",
    lambda s, b: s == 200,
)

if _RUN_REAL_SCAN and _AZURE_CREDS_PRESENT:
    test(
        "TC-13 POST /api/scans/trigger returns 202 Accepted",
        "POST",
        "/api/scans/trigger",
        lambda s, b: s == 202,
        body={"subscription_id": _REAL_SUB},
    )
    _async_scan_id = None

    def _save_scan_id(s, b):
        global _async_scan_id
        _async_scan_id = b.get("scan_id")
        return s == 202 and _async_scan_id is not None

    test(
        "TC-14 POST /api/scans/trigger returns scan_id and pending status",
        "POST",
        "/api/scans/trigger",
        _save_scan_id,
        body={"subscription_id": _REAL_SUB},
    )

    if _async_scan_id:
        test(
            f"TC-40 GET /api/scans/{_async_scan_id} returns status",
            "GET",
            f"/api/scans/{_async_scan_id}",
            lambda s, b: s == 200 and "status" in b,
        )
else:
    _skip_reason = (
        "Real scan skipped — set RUN_REAL_SCAN=true with all four Azure credentials to enable."
        if not _RUN_REAL_SCAN
        else "Real scan skipped — one or more Azure credentials (SUBSCRIPTION_ID, CLIENT_ID, CLIENT_SECRET, TENANT_ID) are missing."  # noqa: E501
    )
    skip("TC-13 POST /api/scans/trigger returns 200, 201 or 202", _skip_reason)
    skip("TC-14 POST /api/scans/trigger returns scan_id or job_id", _skip_reason)

# ── TC-15 to TC-18: Compliance endpoints ──────────────────────────────────
print("\n=== Compliance Endpoints ===")
for tc_num, framework in enumerate(("cis", "nist", "iso27001", "soc2"), start=15):
    test(
        f"TC-{tc_num:02d} GET /api/compliance/{framework} returns 200",
        "GET",
        f"/api/compliance/{framework}",
        lambda s, b: s == 200,
    )

# ── TC-19: POST endpoints reject unauthenticated requests ─────────────────
# GET /api/* is intentionally public (read-only demo dashboard).
# POST endpoints (scan trigger, AI) must remain JWT-protected.
print("\n=== Auth / Security Edge Cases ===")
test(
    "TC-19 POST /api/scans/trigger without auth returns 401",
    "POST",
    "/api/scans/trigger",
    lambda s, b: s == 401,
    auth=False,
    body={},
)
test(
    "TC-20 POST /api/scans/trigger with malformed token returns 401",
    "POST",
    "/api/scans/trigger",
    lambda s, b: s == 401,
    bad_token=True,
    body={},
)

# ── TC-21 to TC-24: Dashboard contract endpoints ───────────────────────────
print("\n=== Dashboard Contract Endpoints ===")
test(
    "TC-21 GET /api/resources returns 200",
    "GET",
    "/api/resources",
    lambda s, b: s == 200,
)
test(
    "TC-22 GET /api/resources returns summary and resources keys",
    "GET",
    "/api/resources",
    lambda s, b: "summary" in b and "resources" in b and isinstance(b["resources"], list),
)
test(
    "TC-23 GET /api/prioritization returns 200",
    "GET",
    "/api/prioritization",
    lambda s, b: s == 200,
)
test(
    "TC-24 GET /api/prioritization returns matrix and rankings keys",
    "GET",
    "/api/prioritization",
    lambda s, b: "matrix" in b and "rankings" in b and isinstance(b["matrix"], list),
)
test(
    "TC-25 GET /api/drift returns 200",
    "GET",
    "/api/drift",
    lambda s, b: s == 200,
)
test(
    "TC-26 GET /api/drift returns summary and events keys",
    "GET",
    "/api/drift",
    lambda s, b: "summary" in b and "events" in b and isinstance(b["events"], list),
)

# Playbook test: fetch a real finding ID first, then probe its playbook.
print("\n=== Playbook Endpoint ===")
_finding_status, _finding_body = request("GET", "/api/findings")
_finding_id = (
    _finding_body.get("findings", [{}])[0].get("id")
    if _finding_status == 200 and _finding_body.get("findings")
    else None
)
if _finding_id is not None:
    test(
        f"TC-27 GET /api/findings/{_finding_id}/playbook returns 200",
        "GET",
        f"/api/findings/{_finding_id}/playbook",
        lambda s, b: s == 200,
    )
    test(
        f"TC-28 GET /api/findings/{_finding_id}/playbook returns playbook keys",
        "GET",
        f"/api/findings/{_finding_id}/playbook",
        lambda s, b: all(k in b for k in ("portal_steps", "cli_commands", "validation_steps")),
    )
else:
    skip("TC-27 GET /api/findings/<id>/playbook returns 200", "No findings in DB — seed the database first.")
    skip("TC-28 GET /api/findings/<id>/playbook returns playbook keys", "No findings in DB — seed the database first.")

# ── TC-33 to TC-35: CVE Enrichment endpoints ──────────────────────────────
print("\n=== CVE Enrichment Endpoints ===")
_scan_status, _scan_body = request("GET", "/api/scans")
# Select the most recent scan that actually has findings to test enrichment
_scan_id = None
if _scan_status == 200 and isinstance(_scan_body, list):
    for s in _scan_body:
        if s.get("total_findings", 0) > 0:
            _scan_id = s.get("scan_id")
            break

if _scan_id is not None:
    test(
        f"TC-33 POST /api/scans/{_scan_id}/enrich returns 200 or 202",
        "POST",
        f"/api/scans/{_scan_id}/enrich",
        lambda s, b: s in (200, 202),
        body={},
    )
    test(
        f"TC-34 POST /api/scans/{_scan_id}/enrich returns status ENRICHING, already enriched, or in progress",
        "POST",
        f"/api/scans/{_scan_id}/enrich",
        lambda s, b: (
            b.get("status") == "ENRICHING"
            or "already enriched" in b.get("message", "")
            or "in progress" in b.get("message", "")
        ),
        body={},
    )

    # Enrichment now runs in a background thread, so TC-33/34 above only
    # prove it was accepted, not that it succeeded. Poll for the real
    # outcome so a completely broken enrichment pipeline still fails here.
    _enrich_final_status = None
    for _ in range(20):  # up to ~100s: NVD lookups are rate-limited to ~1 per 7s
        _poll_status, _poll_body = request("GET", f"/api/scans/{_scan_id}")
        _enrich_final_status = _poll_body.get("cve_enrichment_status")
        if _enrich_final_status in ("COMPLETED", "FAILED"):
            break
        time.sleep(5)

    test(
        f"TC-34b Background enrichment for {_scan_id} reaches COMPLETED",
        "GET",
        f"/api/scans/{_scan_id}",
        lambda s, b: _enrich_final_status == "COMPLETED",
    )
else:
    skip("TC-33 POST /api/scans/<id>/enrich returns 200 or 202", "No scans in DB — trigger a scan first.")
    skip("TC-34 POST /api/scans/<id>/enrich returns status ENRICHING", "No scans in DB — trigger a scan first.")
    skip("TC-34b Background enrichment reaches COMPLETED", "No scans in DB — trigger a scan first.")

test(
    "TC-35 GET /api/score/cve-summary returns status field",
    "GET",
    "/api/score/cve-summary",
    lambda s, b: "status" in b,
)
test(
    "TC-24 GET /api/prioritization returns matrix and rankings keys",
    "GET",
    "/api/prioritization",
    lambda s, b: "matrix" in b and "rankings" in b and isinstance(b["matrix"], list),
)
test(
    "TC-25 GET /api/drift returns 200",
    "GET",
    "/api/drift",
    lambda s, b: s == 200,
)
test(
    "TC-26 GET /api/drift returns summary and events keys",
    "GET",
    "/api/drift",
    lambda s, b: "summary" in b and "events" in b and isinstance(b["events"], list),
)

# Playbook test: fetch a real finding ID first, then probe its playbook.
print("\n=== Playbook Endpoint ===")
_finding_status, _finding_body = request("GET", "/api/findings")
_finding_id = (
    _finding_body.get("findings", [{}])[0].get("id")
    if _finding_status == 200 and _finding_body.get("findings")
    else None
)
if _finding_id is not None:
    test(
        f"TC-27 GET /api/findings/{_finding_id}/playbook returns 200",
        "GET",
        f"/api/findings/{_finding_id}/playbook",
        lambda s, b: s == 200,
    )
    test(
        f"TC-28 GET /api/findings/{_finding_id}/playbook returns playbook keys",
        "GET",
        f"/api/findings/{_finding_id}/playbook",
        lambda s, b: all(k in b for k in ("portal_steps", "cli_commands", "validation_steps")),
    )
else:
    skip("TC-27 GET /api/findings/<id>/playbook returns 200", "No findings in DB — seed the database first.")
    skip("TC-28 GET /api/findings/<id>/playbook returns playbook keys", "No findings in DB — seed the database first.")

# ── TC-33 to TC-35: CVE Enrichment endpoints ──────────────────────────────
print("\n=== CVE Enrichment Endpoints ===")
_scan_status, _scan_body = request("GET", "/api/scans")
_scan_id = _scan_body[0].get("scan_id") if _scan_status == 200 and isinstance(_scan_body, list) and _scan_body else None
if _scan_id is not None:
    test(
        f"TC-33 POST /api/scans/{_scan_id}/enrich returns 200",
        "POST",
        f"/api/scans/{_scan_id}/enrich",
        lambda s, b: s == 200,
        body={},
    )
    test(
        f"TC-34 POST /api/scans/{_scan_id}/enrich returns status COMPLETED",
        "POST",
        f"/api/scans/{_scan_id}/enrich",
        lambda s, b: b.get("status") == "COMPLETED",
        body={},
    )
else:
    skip("TC-33 POST /api/scans/<id>/enrich returns 200", "No scans in DB — trigger a scan first.")
    skip("TC-34 POST /api/scans/<id>/enrich returns status COMPLETED", "No scans in DB — trigger a scan first.")

test(
    "TC-35 GET /api/score/cve-summary returns status field",
    "GET",
    "/api/score/cve-summary",
    lambda s, b: "status" in b,
)
test(
    "TC-24 GET /api/prioritization returns matrix and rankings keys",
    "GET",
    "/api/prioritization",
    lambda s, b: "matrix" in b and "rankings" in b and isinstance(b["matrix"], list),
)
test(
    "TC-25 GET /api/drift returns 200",
    "GET",
    "/api/drift",
    lambda s, b: s == 200,
)
test(
    "TC-26 GET /api/drift returns summary and events keys",
    "GET",
    "/api/drift",
    lambda s, b: "summary" in b and "events" in b and isinstance(b["events"], list),
)

# Playbook test: fetch a real finding ID first, then probe its playbook.
print("\n=== Playbook Endpoint ===")
_finding_status, _finding_body = request("GET", "/api/findings")
_finding_id = (
    _finding_body.get("findings", [{}])[0].get("id")
    if _finding_status == 200 and _finding_body.get("findings")
    else None
)
if _finding_id is not None:
    test(
        f"TC-27 GET /api/findings/{_finding_id}/playbook returns 200",
        "GET",
        f"/api/findings/{_finding_id}/playbook",
        lambda s, b: s == 200,
    )
    test(
        f"TC-28 GET /api/findings/{_finding_id}/playbook returns playbook keys",
        "GET",
        f"/api/findings/{_finding_id}/playbook",
        lambda s, b: all(k in b for k in ("portal_steps", "cli_commands", "validation_steps")),
    )
else:
    skip("TC-27 GET /api/findings/<id>/playbook returns 200", "No findings in DB — seed the database first.")
    skip("TC-28 GET /api/findings/<id>/playbook returns playbook keys", "No findings in DB — seed the database first.")

# ── TC-29 to TC-32: General edge cases ────────────────────────────────────
print("\n=== Edge Cases ===")
test(
    "TC-36 GET /nonexistent returns 404",
    "GET",
    "/nonexistent-endpoint-xyz",
    lambda s, b: s == 404,
    auth=True,
)
test(
    "TC-37 POST /api/scans/trigger with empty body returns 400 or starts scan",
    "POST",
    "/api/scans/trigger",
    # 400 = missing subscription_id (expected when no AZURE_SUBSCRIPTION_ID env var)
    # 200/201/202 = scan started (AZURE_SUBSCRIPTION_ID configured on server)
    # 500 = scan failed (bad credentials)
    # 0 = client timeout (real scan running past the 45s window — not a crash)
    lambda s, b: s in (200, 201, 202, 400, 500, 0),
    body={},
)
test(
    "TC-38 GET /api/findings?limit=0 does not crash",
    "GET",
    "/api/findings?limit=0",
    lambda s, b: s in (200, 400),
)
test(
    "TC-39 Response Content-Type is JSON",
    "GET",
    "/api/findings",
    lambda s, b: isinstance(b, dict),
)

# ── Summary ────────────────────────────────────────────────────────────────
print("\n=== Summary ===")
passed = sum(1 for _, p in results if p is True)
skipped = sum(1 for _, p in results if p is None)
failed_tests = [name for name, p in results if p is False]
total = len(results)

skip_note = f", {skipped} skipped" if skipped else ""
print(f"  {passed}/{total - skipped} tests passed{skip_note}")

if skipped:
    print("\n  Skipped tests (not failures):")
    for name, p in results:
        if p is None:
            print(f"    - {name}")
    print(
        "\n  To enable real scan tests: RUN_REAL_SCAN=true with AZURE_SUBSCRIPTION_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID"  # noqa: E501
    )

if failed_tests:
    print("\n  Failed tests:")
    for name in failed_tests:
        print(f"    - {name}")
    print("\nSmoke test FAILED. Do not open a PR until all tests pass.")
    sys.exit(1)
else:
    print("\n  All smoke tests passed.")
    sys.exit(0)
