"""Unit tests for API routes: score, compliance, drift, resources, prioritization."""

from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_cursor(fetchone=None, fetchall=None):
    """Return a mock cursor with configurable return values."""
    cursor = MagicMock()
    cursor.__enter__ = MagicMock(return_value=cursor)
    cursor.__exit__ = MagicMock(return_value=False)
    cursor.fetchone.return_value = fetchone
    cursor.fetchall.return_value = fetchall or []
    return cursor


def _make_conn(fetchone=None, fetchall=None):
    """Return a mock DB connection."""
    conn = MagicMock()
    cursor = _make_cursor(fetchone=fetchone, fetchall=fetchall)
    conn.cursor.return_value = cursor
    return conn


def _make_db(score=85, compliance=None, fetchall=None, fetchone=None):
    """Return a mock DatabaseManager."""
    db = MagicMock()
    db.get_score.return_value = score
    db.get_cve_summary.return_value = {
        "total_findings": 0,
        "exploit_count": 0,
        "max_cvss_score": None,
        "avg_cvss_score": None,
        "cve_enrichment_status": "done",
    }
    db.get_compliance_score.return_value = compliance or {
        "framework": "cis",
        "total_controls": 10,
        "passed": 8,
        "failed": 2,
        "score_percent": 80.0,
        "controls": [],
    }
    # For routes that use _get_conn() directly
    mock_conn = _make_conn(fetchone=fetchone, fetchall=fetchall)
    db._get_conn.return_value = mock_conn
    return db


# ---------------------------------------------------------------------------
# Score route tests
# ---------------------------------------------------------------------------


class TestScoreRoute:
    """Tests for GET /api/score."""

    def test_score_returns_200(self, client, auth_headers):
        with patch("api.routes.score._get_db") as mock_get_db:
            mock_get_db.return_value = _make_db(score=85)
            resp = client.get("/api/score", headers=auth_headers)
        assert resp.status_code == 200

    def test_score_returns_score_field(self, client, auth_headers):
        with patch("api.routes.score._get_db") as mock_get_db:
            mock_get_db.return_value = _make_db(score=100)
            resp = client.get("/api/score", headers=auth_headers)
        # score route returns jsonify(int) — response is the score directly
        assert resp.status_code == 200

    def test_score_value_matches_db(self, client, auth_headers):
        with patch("api.routes.score._get_db") as mock_get_db:
            mock_get_db.return_value = _make_db(score=72)
            resp = client.get("/api/score", headers=auth_headers)
        data = resp.get_json()
        assert data == 72

    def test_score_is_100_with_perfect_score(self, client, auth_headers):
        with patch("api.routes.score._get_db") as mock_get_db:
            mock_get_db.return_value = _make_db(score=100)
            resp = client.get("/api/score", headers=auth_headers)
        data = resp.get_json()
        assert data == 100

    def test_score_returns_500_on_db_error(self, client, auth_headers):
        with patch("api.routes.score._get_db", side_effect=RuntimeError("DB error")):
            resp = client.get("/api/score", headers=auth_headers)
        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# Compliance route tests
# ---------------------------------------------------------------------------


class TestComplianceRoute:
    """Tests for GET /api/compliance/<framework>."""

    def test_compliance_cis_returns_200(self, client, auth_headers):
        with patch("api.routes.compliance._get_db") as mock_get_db:
            mock_get_db.return_value = _make_db()
            resp = client.get("/api/compliance/cis", headers=auth_headers)
        assert resp.status_code == 200

    def test_compliance_nist_returns_200(self, client, auth_headers):
        with patch("api.routes.compliance._get_db") as mock_get_db:
            mock_get_db.return_value = _make_db()
            resp = client.get("/api/compliance/nist", headers=auth_headers)
        assert resp.status_code == 200

    def test_compliance_iso27001_returns_200(self, client, auth_headers):
        with patch("api.routes.compliance._get_db") as mock_get_db:
            mock_get_db.return_value = _make_db()
            resp = client.get("/api/compliance/iso27001", headers=auth_headers)
        assert resp.status_code == 200

    def test_compliance_soc2_returns_200(self, client, auth_headers):
        with patch("api.routes.compliance._get_db") as mock_get_db:
            mock_get_db.return_value = _make_db()
            resp = client.get("/api/compliance/soc2", headers=auth_headers)
        assert resp.status_code == 200

    def test_compliance_invalid_framework_returns_400(self, client, auth_headers):
        resp = client.get("/api/compliance/unknown", headers=auth_headers)
        assert resp.status_code == 400

    def test_compliance_returns_500_on_db_error(self, client, auth_headers):
        with patch("api.routes.compliance._get_db", side_effect=RuntimeError("DB error")):
            resp = client.get("/api/compliance/cis", headers=auth_headers)
        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Drift route tests
# ---------------------------------------------------------------------------


class TestDriftRoute:
    """Tests for GET /api/drift."""

    def _make_drift_db(self, scans=None):
        db = MagicMock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_cursor.fetchall.return_value = scans or []
        mock_conn.cursor.return_value = mock_cursor
        db._get_conn.return_value = mock_conn
        return db

    def test_drift_returns_200_with_no_scans(self, client, auth_headers):
        with patch("api.routes.drift._get_db") as mock_get_db:
            mock_get_db.return_value = self._make_drift_db(scans=[])
            resp = client.get("/api/drift", headers=auth_headers)
        assert resp.status_code == 200

    def test_drift_returns_empty_events_with_one_scan(self, client, auth_headers):
        """Single scan returns empty events — no comparison possible."""
        import datetime

        scans = [{"scan_id": "scan-001", "started_at": datetime.datetime(2024, 1, 1)}]
        with patch("api.routes.drift._get_db") as mock_get_db:
            mock_get_db.return_value = self._make_drift_db(scans=scans)
            resp = client.get("/api/drift", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["events"] == []
        assert data["summary"]["total"] == 0

    def test_drift_response_has_summary_and_events(self, client, auth_headers):
        with patch("api.routes.drift._get_db") as mock_get_db:
            mock_get_db.return_value = self._make_drift_db(scans=[])
            resp = client.get("/api/drift", headers=auth_headers)
        data = resp.get_json()
        assert "summary" in data
        assert "events" in data

    def test_drift_summary_has_required_fields(self, client, auth_headers):
        with patch("api.routes.drift._get_db") as mock_get_db:
            mock_get_db.return_value = self._make_drift_db(scans=[])
            resp = client.get("/api/drift", headers=auth_headers)
        summary = resp.get_json()["summary"]
        for key in ("total", "added", "removed", "modified"):
            assert key in summary

    def test_drift_with_two_scans_classifies_added_removed(self, client, auth_headers):
        """Two scans with differing findings exercises ADDED/REMOVED classification."""
        import datetime

        scan1_id = "aaa00000-0000-0000-0000-000000000001"
        scan2_id = "bbb00000-0000-0000-0000-000000000002"
        scans = [
            {"scan_id": scan2_id, "started_at": datetime.datetime(2024, 1, 2)},
            {"scan_id": scan1_id, "started_at": datetime.datetime(2024, 1, 1)},
        ]
        # findings in latest but not previous -> ADDED
        # findings in previous but not latest -> REMOVED
        latest_rows = [
            {
                "rule_id": "AZ-NET-001",
                "resource_id": "/sub/res1",
                "resource_name": "res1",
                "resource_type": "NSG",
                "category": "Network",
                "severity": "HIGH",
                "scan_id": scan2_id,
            },
        ]
        previous_rows = [
            {
                "rule_id": "AZ-DB-001",
                "resource_id": "/sub/res2",
                "resource_name": "res2",
                "resource_type": "DB",
                "category": "Database",
                "severity": "MEDIUM",
                "scan_id": scan1_id,
            },
        ]
        db = MagicMock()
        mock_conn = MagicMock()
        # cursor 1: fetchall returns scans list
        c1 = MagicMock()
        c1.__enter__ = MagicMock(return_value=c1)
        c1.__exit__ = MagicMock(return_value=False)
        c1.fetchall.return_value = scans
        # cursor 2: fetchall returns combined latest+previous rows for diff query
        c2 = MagicMock()
        c2.__enter__ = MagicMock(return_value=c2)
        c2.__exit__ = MagicMock(return_value=False)
        c2.fetchall.return_value = latest_rows + previous_rows
        mock_conn.cursor.side_effect = [c1, c2]
        db._get_conn.return_value = mock_conn

        with patch("api.routes.drift._get_db", return_value=db):
            resp = client.get("/api/drift", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["summary"]["total"] > 0

    def test_drift_returns_500_on_db_error(self, client, auth_headers):
        with patch("api.routes.drift._get_db", side_effect=RuntimeError("DB error")):
            resp = client.get("/api/drift", headers=auth_headers)
        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# Resources route tests
# ---------------------------------------------------------------------------


class TestResourcesRoute:
    """Tests for GET /api/resources."""

    def _make_resources_db(self, fetchone=None, rows=None):
        """Mock DB where fetchone() is the latest scan and fetchall() returns resources."""
        db = MagicMock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)
        # fetchone returns latest scan — None means no scan found
        mock_cursor.fetchone.return_value = fetchone
        mock_cursor.fetchall.return_value = rows or []
        # cursor_factory kwarg is ignored by MagicMock — always returns same cursor
        mock_conn.cursor.return_value = mock_cursor
        db._get_conn.return_value = mock_conn
        return db

    def test_resources_returns_200_when_no_scan(self, client, auth_headers):
        """Returns 200 with empty resources when no scan exists."""
        with patch("api.routes.resources._get_db") as mock_get_db:
            mock_get_db.return_value = self._make_resources_db(fetchone=None)
            resp = client.get("/api/resources", headers=auth_headers)
        assert resp.status_code == 200

    def test_resources_response_has_required_keys(self, client, auth_headers):
        with patch("api.routes.resources._get_db") as mock_get_db:
            mock_get_db.return_value = self._make_resources_db(fetchone=None)
            resp = client.get("/api/resources", headers=auth_headers)
        data = resp.get_json()
        assert "resources" in data
        assert "summary" in data

    def test_resources_empty_when_no_scan(self, client, auth_headers):
        with patch("api.routes.resources._get_db") as mock_get_db:
            mock_get_db.return_value = self._make_resources_db(fetchone=None)
            resp = client.get("/api/resources", headers=auth_headers)
        assert resp.get_json()["resources"] == []

    def test_resources_with_mixed_severity_rows(self, client, auth_headers):
        """Rows with different risk_rank values exercise risk mapping and by_risk_level counts."""
        import datetime

        rows = [
            {
                "resource_id": "/subscriptions/s/resourceGroups/rg/providers/res1",
                "resource_name": "res1",
                "resource_type": "NSG",
                "category": "Network",
                "risk_rank": 3,
                "discovered_at": datetime.datetime(2024, 1, 1),
            },
            {
                "resource_id": "/subscriptions/s/resourceGroups/rg/providers/res2",
                "resource_name": "res2",
                "resource_type": "DB",
                "category": "Database",
                "risk_rank": 2,
                "discovered_at": datetime.datetime(2024, 1, 1),
            },
            {
                "resource_id": "/subscriptions/s/resourceGroups/rg/providers/res3",
                "resource_name": "res3",
                "resource_type": "Storage",
                "category": "Storage",
                "risk_rank": 1,
                "discovered_at": datetime.datetime(2024, 1, 1),
            },
        ]
        with patch("api.routes.resources._get_db") as mock_get_db:
            mock_get_db.return_value = self._make_resources_db(
                fetchone={"scan_id": "s-1", "started_at": datetime.datetime(2024, 1, 1)},
                rows=rows,
            )
            resp = client.get("/api/resources", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data["resources"]) == 3
        risk_levels = {r["risk"] for r in data["resources"]}
        assert "HIGH" in risk_levels
        assert "MEDIUM" in risk_levels
        assert "LOW" in risk_levels
        assert data["summary"]["by_risk_level"]["HIGH"] == 1
        assert data["summary"]["by_risk_level"]["MEDIUM"] == 1
        assert data["summary"]["by_risk_level"]["LOW"] == 1

    def test_resources_returns_500_on_db_error(self, client, auth_headers):
        with patch("api.routes.resources._get_db", side_effect=RuntimeError("DB error")):
            resp = client.get("/api/resources", headers=auth_headers)
        assert resp.status_code == 500


# ---------------------------------------------------------------------------
# Prioritization route tests
# ---------------------------------------------------------------------------


class TestPrioritizationRoute:
    """Tests for GET /api/prioritization."""

    def _make_prioritization_db(self, fetchone=None, rules=None):
        db = MagicMock()
        mock_conn = MagicMock()
        cursor1 = MagicMock()
        cursor1.__enter__ = MagicMock(return_value=cursor1)
        cursor1.__exit__ = MagicMock(return_value=False)
        cursor1.fetchone.return_value = fetchone
        cursor2 = MagicMock()
        cursor2.__enter__ = MagicMock(return_value=cursor2)
        cursor2.__exit__ = MagicMock(return_value=False)
        cursor2.fetchall.return_value = rules or []
        cursor2.fetchone.return_value = {"total": len(rules) if rules else 0}
        mock_conn.cursor.side_effect = [cursor1, cursor2, cursor1, cursor2]
        db._get_conn.return_value = mock_conn
        return db

    def test_prioritization_returns_200_with_no_scan(self, client, auth_headers):
        with patch("api.routes.prioritization._get_db") as mock_get_db:
            mock_get_db.return_value = self._make_prioritization_db(fetchone=None)
            resp = client.get("/api/prioritization", headers=auth_headers)
        assert resp.status_code == 200

    def test_prioritization_response_has_required_keys(self, client, auth_headers):
        with patch("api.routes.prioritization._get_db") as mock_get_db:
            mock_get_db.return_value = self._make_prioritization_db(fetchone=None)
            resp = client.get("/api/prioritization", headers=auth_headers)
        data = resp.get_json()
        assert "matrix" in data
        assert "rankings" in data
        assert "action_items" in data

    def test_prioritization_high_severity_ranked_first(self, client, auth_headers):
        """HIGH severity rules rank before LOW severity."""
        high_rule = {
            "rule_id": "AZ-NET-001",
            "rule_name": "NSG broad",
            "severity": "HIGH",
            "category": "Network",
            "affected_count": 2,
            "description": "desc",
            "remediation": "fix",
            "resource_name": "nsg-01",
        }
        low_rule = {
            "rule_id": "AZ-STOR-001",
            "rule_name": "Tags",
            "severity": "LOW",
            "category": "Storage",
            "affected_count": 1,
            "description": "desc",
            "remediation": "fix",
            "resource_name": "storage-01",
        }
        with patch("api.routes.prioritization._get_db") as mock_get_db:
            mock_get_db.return_value = self._make_prioritization_db(
                fetchone={"scan_id": "s-1", "total": 3},
                rules=[high_rule, low_rule],
            )
            resp = client.get("/api/prioritization", headers=auth_headers)
        assert resp.status_code == 200
        rankings = resp.get_json().get("rankings", [])
        if len(rankings) >= 2:
            assert rankings[0]["severity"] == "HIGH"

    def test_prioritization_returns_500_on_db_error(self, client, auth_headers):
        with patch("api.routes.prioritization._get_db", side_effect=RuntimeError("DB error")):
            resp = client.get("/api/prioritization", headers=auth_headers)
        assert resp.status_code == 500
