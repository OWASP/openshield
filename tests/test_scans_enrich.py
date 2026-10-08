"""Tests for durable POST /api/scans/<id>/enrich job admission."""

from unittest.mock import MagicMock, patch

import api.routes.scans as scans_route


_SCAN_ID = "00000000-0000-0000-0000-000000000001"
_JOB_ID = "00000000-0000-0000-0000-0000000000aa"


def _mock_db(current_scan=None, findings=None):
    db = MagicMock()
    db.get_scan.return_value = current_scan
    db.get_findings.return_value = findings if findings is not None else []
    return db


def test_enrich_returns_202_and_enqueues_durable_job(client, auth_headers):
    scan = {"scan_id": _SCAN_ID, "cve_enrichment_status": "PENDING"}
    db = _mock_db(current_scan=scan, findings=[{"id": 1, "rule_id": "AZ-STOR-001"}])
    db.enqueue_enrichment_job.return_value = ({"job_id": _SCAN_ID, "status": "pending"}, "created")

    with patch.object(scans_route, "_get_db", return_value=db):
        resp = client.post(f"/api/scans/{_SCAN_ID}/enrich", headers=auth_headers)

    assert resp.status_code == 202
    body = resp.get_json()
    assert body["outcome"] == "created"
    assert body["status"] == "pending"
    assert body["job_id"] == _SCAN_ID
    db.enqueue_enrichment_job.assert_called_once_with(_SCAN_ID)


def test_enrich_reuses_existing_durable_job(client, auth_headers):
    scan = {"scan_id": _SCAN_ID, "cve_enrichment_status": "PENDING"}
    db = _mock_db(current_scan=scan, findings=[{"id": 1}])
    db.enqueue_enrichment_job.return_value = ({"job_id": _SCAN_ID, "status": "running"}, "active")
    with patch.object(scans_route, "_get_db", return_value=db):
        resp = client.post(f"/api/scans/{_SCAN_ID}/enrich", headers=auth_headers)
    assert resp.status_code == 202
    body = resp.get_json()
    assert body["outcome"] == "active"
    assert body["status"] == "running"


def test_enrich_requeues_a_terminally_failed_job(client, auth_headers):
    """A failed job is the case a re-POST exists to recover from."""
    scan = {"scan_id": _SCAN_ID, "cve_enrichment_status": "FAILED"}
    db = _mock_db(current_scan=scan, findings=[{"id": 1}])
    db.enqueue_enrichment_job.return_value = ({"job_id": _SCAN_ID, "status": "pending"}, "requeued")
    with patch.object(scans_route, "_get_db", return_value=db):
        resp = client.post(f"/api/scans/{_SCAN_ID}/enrich", headers=auth_headers)
    assert resp.status_code == 202
    body = resp.get_json()
    assert body["outcome"] == "requeued"
    assert body["status"] == "pending"
    assert "requeued" in body["message"]


def test_enrich_reports_an_already_completed_job_without_restarting_it(client, auth_headers):
    # The scan header still reads PENDING, so the job row is the authority.
    scan = {"scan_id": _SCAN_ID, "cve_enrichment_status": "PENDING"}
    db = _mock_db(current_scan=scan, findings=[{"id": 1}])
    db.enqueue_enrichment_job.return_value = ({"job_id": _SCAN_ID, "status": "completed"}, "completed")
    with patch.object(scans_route, "_get_db", return_value=db):
        resp = client.post(f"/api/scans/{_SCAN_ID}/enrich", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.get_json()["outcome"] == "completed"


def test_enrich_already_completed_uses_the_canonical_response(client, auth_headers):
    """An enriched scan answers in the documented {outcome, job_id} shape.

    This used to short-circuit to {message, scan_id}, which is neither the
    documented contract nor what any other outcome returns.
    """
    scan = {"scan_id": _SCAN_ID, "cve_enrichment_status": "COMPLETED"}
    # A clean scan can finish enrichment with nothing to enrich, so findings
    # are deliberately empty here: completion must still win over the 404.
    db = _mock_db(current_scan=scan, findings=[])
    db.enqueue_enrichment_job.return_value = ({"job_id": _JOB_ID, "status": "completed"}, "completed")
    with patch.object(scans_route, "_get_db", return_value=db):
        resp = client.post(f"/api/scans/{_SCAN_ID}/enrich", headers=auth_headers)

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["outcome"] == "completed"
    assert body["job_id"] == _JOB_ID
    assert body["status"] == "completed"
    assert body["scan_id"] == _SCAN_ID
    assert "already enriched" in body["message"]
    db.enqueue_enrichment_job.assert_called_once_with(_SCAN_ID)


def test_enrich_responses_share_one_contract_across_every_outcome(client, auth_headers):
    """created/requeued/active/completed all return the same keys."""
    expected = {"scan_id", "job_id", "status", "outcome", "message"}
    cases = [
        ("created", "pending", 202),
        ("requeued", "pending", 202),
        ("active", "running", 202),
        ("completed", "completed", 200),
    ]
    for outcome, job_status, code in cases:
        scan = {"scan_id": _SCAN_ID, "cve_enrichment_status": "PENDING"}
        db = _mock_db(current_scan=scan, findings=[{"id": 1}])
        db.enqueue_enrichment_job.return_value = ({"job_id": _JOB_ID, "status": job_status}, outcome)
        with patch.object(scans_route, "_get_db", return_value=db):
            resp = client.post(f"/api/scans/{_SCAN_ID}/enrich", headers=auth_headers)
        assert resp.status_code == code, outcome
        assert set(resp.get_json()) == expected, outcome
        assert resp.get_json()["outcome"] == outcome


def test_enrich_missing_scan_returns_404(client, auth_headers):
    with patch.object(scans_route, "_get_db", return_value=_mock_db(current_scan=None)):
        resp = client.post(f"/api/scans/{_SCAN_ID}/enrich", headers=auth_headers)
    assert resp.status_code == 404


def test_enrich_no_findings_returns_404(client, auth_headers):
    scan = {"scan_id": _SCAN_ID, "cve_enrichment_status": "PENDING"}
    with patch.object(scans_route, "_get_db", return_value=_mock_db(current_scan=scan, findings=[])):
        resp = client.post(f"/api/scans/{_SCAN_ID}/enrich", headers=auth_headers)
    assert resp.status_code == 404
