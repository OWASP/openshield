"""Tests that API error responses never leak exception internals (issue #177,
CodeQL: information exposure through an exception).

Each route's _get_db() (or equivalent) is patched to raise, mirroring the
established per-module DB-mocking convention (see test_findings_playbook.py).
A secret-shaped marker string is used as the exception message so a leak
would be unambiguous rather than coincidentally matching real wording.
"""

from unittest.mock import MagicMock, patch

import api.routes.compliance as compliance_route
import api.routes.drift as drift_route
import api.routes.findings as findings_route
import api.routes.prioritization as prioritization_route
import api.routes.resources as resources_route
import api.routes.scans as scans_route
import api.routes.score as score_route

_LEAK_MARKER = "connection to db-internal-host-secret-1234 refused"


def _raising_db(method_name):
    db = MagicMock()
    getattr(db, method_name).side_effect = RuntimeError(_LEAK_MARKER)
    return db


def _assert_no_leak(resp, expected_status):
    assert resp.status_code == expected_status
    body = resp.get_json()
    assert "detail" not in body
    assert _LEAK_MARKER not in str(body)


def test_list_scans_error_does_not_leak_exception(client, auth_headers):
    with patch.object(scans_route, "_get_db", return_value=_raising_db("get_scans")):
        resp = client.get("/api/scans", headers=auth_headers)
    _assert_no_leak(resp, 500)


def test_get_scan_status_error_does_not_leak_exception(client, auth_headers):
    with patch.object(scans_route, "_get_db", return_value=_raising_db("get_scan")):
        resp = client.get("/api/scans/00000000-0000-0000-0000-000000000001", headers=auth_headers)
    _assert_no_leak(resp, 500)


def test_trigger_scan_db_error_does_not_leak_exception(client, auth_headers):
    with patch.object(scans_route, "_get_db", return_value=_raising_db("admit_scan")):
        resp = client.post(
            "/api/scans/trigger",
            json={"subscription_id": "00000000-0000-0000-0000-000000000001"},
            headers=auth_headers,
        )
    _assert_no_leak(resp, 500)


def test_list_findings_error_does_not_leak_exception(client, auth_headers):
    with patch.object(findings_route, "_get_db", return_value=_raising_db("get_findings")):
        resp = client.get("/api/findings", headers=auth_headers)
    _assert_no_leak(resp, 500)


def test_get_finding_error_does_not_leak_exception(client, auth_headers):
    with patch.object(findings_route, "_get_db", return_value=_raising_db("get_finding_by_id")):
        resp = client.get("/api/findings/1", headers=auth_headers)
    _assert_no_leak(resp, 500)


def test_get_playbook_error_does_not_leak_exception(client, auth_headers):
    with patch.object(findings_route, "_get_db", return_value=_raising_db("get_finding_by_id")):
        resp = client.get("/api/findings/1/playbook", headers=auth_headers)
    _assert_no_leak(resp, 500)


def test_score_error_does_not_leak_exception(client, auth_headers):
    with patch.object(score_route, "_get_db", return_value=_raising_db("get_score")):
        resp = client.get("/api/score", headers=auth_headers)
    _assert_no_leak(resp, 500)


def test_cve_summary_error_does_not_leak_exception(client, auth_headers):
    with patch.object(score_route, "_get_db", return_value=_raising_db("get_cve_summary")):
        resp = client.get("/api/score/cve-summary", headers=auth_headers)
    _assert_no_leak(resp, 500)


def test_resources_error_does_not_leak_exception(client, auth_headers):
    with patch.object(resources_route, "_get_db", return_value=_raising_db("get_findings")):
        resp = client.get("/api/resources", headers=auth_headers)
    _assert_no_leak(resp, 500)


def test_prioritization_error_does_not_leak_exception(client, auth_headers):
    with patch.object(prioritization_route, "_get_db", return_value=_raising_db("_get_conn")):
        resp = client.get("/api/prioritization", headers=auth_headers)
    _assert_no_leak(resp, 500)


def test_drift_error_does_not_leak_exception(client, auth_headers):
    with patch.object(drift_route, "_get_db", return_value=_raising_db("get_findings")):
        resp = client.get("/api/drift", headers=auth_headers)
    _assert_no_leak(resp, 500)


def test_compliance_generic_error_does_not_leak_exception(client, auth_headers):
    with patch.object(compliance_route, "_get_db", return_value=_raising_db("get_compliance_score")):
        resp = client.get("/api/compliance/cis", headers=auth_headers)
    _assert_no_leak(resp, 500)


def test_compliance_missing_frameworks_dir_does_not_leak_exception(client, auth_headers):
    db = MagicMock()
    db.get_compliance_score.side_effect = FileNotFoundError(_LEAK_MARKER)
    with patch.object(compliance_route, "_get_db", return_value=db):
        resp = client.get("/api/compliance/cis", headers=auth_headers)
    _assert_no_leak(resp, 500)


def test_bad_request_errorhandler_does_not_leak_exception(client, auth_headers):
    resp = client.post(
        "/api/scans/trigger",
        data=b"{not valid json",
        headers={**auth_headers, "Content-Type": "application/json"},
    )
    body = resp.get_json()
    assert "detail" not in body
