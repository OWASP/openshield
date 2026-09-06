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
