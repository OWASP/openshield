"""Route-level contract tests for GET /api/score.

get_score() moved from a bare integer to {status, score, max_score} so
NO_SCAN_DATA can be reported explicitly instead of a false 100 (issue #302).
These tests pin the actual HTTP response shape for both states, since the
frontend, API reference docs, and any external consumer all depend on it.
"""

from unittest.mock import MagicMock, patch

import api.routes.score as score_route


def test_route_returns_ok_status_and_max_score_for_a_real_score(client, auth_headers):
    db = MagicMock()
    db.get_score.return_value = {"status": "OK", "score": 82, "max_score": 100}
    with patch.object(score_route, "_get_db", return_value=db):
        resp = client.get("/api/score", headers=auth_headers)

    assert resp.status_code == 200
    body = resp.get_json()
    assert body == {"status": "OK", "score": 82, "max_score": 100}


def test_route_returns_200_with_null_score_for_no_scan_data(client, auth_headers):
    """A missing scan must surface as a normal 200 with an explicit
    NO_SCAN_DATA status and a null score - never a 500, and never a score
    value that looks like a real evaluated result."""
    db = MagicMock()
    db.get_score.return_value = {
        "status": "NO_SCAN_DATA",
        "score": None,
        "max_score": 100,
        "message": "No completed scan is available yet, so there is no security posture to score.",
    }
    with patch.object(score_route, "_get_db", return_value=db):
        resp = client.get("/api/score", headers=auth_headers)

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "NO_SCAN_DATA"
    assert body["score"] is None
    assert body["max_score"] == 100
    assert "error" not in body


def test_route_passes_subscription_id_through_to_the_model(client, auth_headers, monkeypatch):
    """?subscription_id= must scope the score, matching the contract
    /api/compliance/<framework> already honours. Previously get_score() read
    a non-existent instance attribute, so every production call was
    unscoped and a shared-database deployment could score another
    subscription's latest scan."""
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    sub = "11111111-2222-3333-4444-555555555555"
    db = MagicMock()
    db.get_score.return_value = {"status": "OK", "score": 70, "max_score": 100}
    with patch.object(score_route, "_get_db", return_value=db):
        resp = client.get(f"/api/score?subscription_id={sub}", headers=auth_headers)

    assert resp.status_code == 200
    db.get_score.assert_called_once_with(subscription_id=sub)


def test_route_falls_back_to_the_configured_default_subscription(client, auth_headers, monkeypatch):
    """With no query parameter the deployment's own AZURE_SUBSCRIPTION_ID is
    used, the same fallback POST /api/scans and the compliance route apply."""
    sub = "11111111-2222-3333-4444-555555555555"
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", sub)
    db = MagicMock()
    db.get_score.return_value = {"status": "OK", "score": 70, "max_score": 100}
    with patch.object(score_route, "_get_db", return_value=db):
        resp = client.get("/api/score", headers=auth_headers)

    assert resp.status_code == 200
    db.get_score.assert_called_once_with(subscription_id=sub)


def test_route_rejects_a_malformed_subscription_id(client, auth_headers, monkeypatch):
    """A non-UUID subscription_id is a 400, not a silently unscoped score."""
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    db = MagicMock()
    with patch.object(score_route, "_get_db", return_value=db):
        resp = client.get("/api/score?subscription_id=not-a-uuid", headers=auth_headers)

    assert resp.status_code == 400
    db.get_score.assert_not_called()
