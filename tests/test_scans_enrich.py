"""Tests for durable POST /api/scans/<id>/enrich job admission."""

from unittest.mock import MagicMock, patch

import api.routes.scans as scans_route


_SCAN_ID = "00000000-0000-0000-0000-000000000001"


def _mock_db(current_scan=None, findings=None):
    db = MagicMock()
    db.get_scan.return_value = current_scan
    db.get_findings.return_value = findings if findings is not None else []
    return db


def test_enrich_returns_202_and_enqueues_durable_job(client, auth_headers):
    scan = {"scan_id": _SCAN_ID, "cve_enrichment_status": "PENDING"}
    db = _mock_db(current_scan=scan, findings=[{"id": 1, "rule_id": "AZ-STOR-001"}])
    db.enqueue_enrichment_job.return_value = ({"job_id": _SCAN_ID, "status": "pending"}, True)

    with patch.object(scans_route, "_get_db", return_value=db):
        resp = client.post(f"/api/scans/{_SCAN_ID}/enrich", headers=auth_headers)

    assert resp.status_code == 202
    assert resp.get_json()["status"] == "PENDING"
    db.enqueue_enrichment_job.assert_called_once_with(_SCAN_ID)


def test_enrich_reuses_existing_durable_job(client, auth_headers):
    scan = {"scan_id": _SCAN_ID, "cve_enrichment_status": "PENDING"}
    db = _mock_db(current_scan=scan, findings=[{"id": 1}])
    db.enqueue_enrichment_job.return_value = ({"job_id": _SCAN_ID, "status": "running"}, False)
    with patch.object(scans_route, "_get_db", return_value=db):
        resp = client.post(f"/api/scans/{_SCAN_ID}/enrich", headers=auth_headers)
    assert resp.status_code == 202
    assert resp.get_json()["status"] == "running"


def test_enrich_already_completed_returns_200(client, auth_headers):
    scan = {"scan_id": _SCAN_ID, "cve_enrichment_status": "COMPLETED"}
    db = _mock_db(current_scan=scan)
    with patch.object(scans_route, "_get_db", return_value=db):
        resp = client.post(f"/api/scans/{_SCAN_ID}/enrich", headers=auth_headers)
    assert resp.status_code == 200
    assert "already enriched" in resp.get_json()["message"]


def test_enrich_missing_scan_returns_404(client, auth_headers):
    with patch.object(scans_route, "_get_db", return_value=_mock_db(current_scan=None)):
        resp = client.post(f"/api/scans/{_SCAN_ID}/enrich", headers=auth_headers)
    assert resp.status_code == 404


def test_enrich_no_findings_returns_404(client, auth_headers):
    scan = {"scan_id": _SCAN_ID, "cve_enrichment_status": "PENDING"}
    with patch.object(scans_route, "_get_db", return_value=_mock_db(current_scan=scan, findings=[])):
        resp = client.post(f"/api/scans/{_SCAN_ID}/enrich", headers=auth_headers)
    assert resp.status_code == 404
