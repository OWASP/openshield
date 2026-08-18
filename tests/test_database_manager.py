"""Unit tests for DatabaseManager — connection, CRUD, and scoring logic."""

from unittest.mock import MagicMock

import pytest

from api.models.finding import DatabaseManager, Finding, SEVERITY_WEIGHTS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(**kwargs):
    defaults = {
        "rule_id": "AZ-NET-001",
        "rule_name": "NSG allows broad inbound",
        "severity": "HIGH",
        "category": "Network",
        "resource_id": "/subscriptions/sub-1/rg/rg-1/nsg-1",
        "resource_name": "nsg-1",
        "resource_type": "Microsoft.Network/networkSecurityGroups",
        "description": "NSG allows broad inbound access.",
        "remediation": "Restrict inbound rules.",
        "frameworks": {"CIS": "6.1"},
        "detected_at": "2024-01-01T00:00:00Z",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# Initialisation tests
# ---------------------------------------------------------------------------


class TestDatabaseManagerInit:
    """Tests for DatabaseManager initialisation."""

    def test_init_with_explicit_dsn(self):
        """DatabaseManager accepts an explicit DSN without reading environ."""
        db = DatabaseManager(dsn="postgresql://user:pass@localhost/db")
        assert db.dsn == "postgresql://user:pass@localhost/db"

    def test_init_reads_database_url_from_env(self, monkeypatch):
        """DatabaseManager reads DATABASE_URL when no DSN is provided."""
        monkeypatch.setenv("DATABASE_URL", "postgresql://env:env@localhost/envdb")
        db = DatabaseManager()
        assert db.dsn == "postgresql://env:env@localhost/envdb"

    def test_init_raises_without_dsn_or_env(self, monkeypatch):
        """DatabaseManager raises KeyError when DATABASE_URL is unset."""
        monkeypatch.delenv("DATABASE_URL", raising=False)
        with pytest.raises(KeyError):
            DatabaseManager()

    def test_conn_is_none_before_connect(self):
        """Connection is None before connect() is called."""
        db = DatabaseManager(dsn="postgresql://test:test@localhost/test")
        assert db.conn is None


# ---------------------------------------------------------------------------
# SEVERITY_WEIGHTS tests
# ---------------------------------------------------------------------------


class TestSeverityWeights:
    """Tests for SEVERITY_WEIGHTS constant."""

    def test_high_outweighs_medium(self):
        assert SEVERITY_WEIGHTS["HIGH"] > SEVERITY_WEIGHTS["MEDIUM"]

    def test_medium_outweighs_low(self):
        assert SEVERITY_WEIGHTS["MEDIUM"] > SEVERITY_WEIGHTS["LOW"]

    def test_info_has_zero_weight(self):
        assert SEVERITY_WEIGHTS.get("INFO", 0) == 0

    def test_all_weights_non_negative(self):
        for key, value in SEVERITY_WEIGHTS.items():
            assert value >= 0, f"{key} has negative weight"


# ---------------------------------------------------------------------------
# Finding dataclass tests
# ---------------------------------------------------------------------------


class TestFindingDataclass:
    """Tests for the Finding dataclass."""

    def test_finding_creation_with_required_fields(self):
        """Finding can be created with required fields."""
        finding = _make_finding()
        assert finding.rule_id == "AZ-NET-001"
        assert finding.severity == "HIGH"

    def test_finding_to_dict_returns_dict(self):
        """to_dict() returns a dictionary."""
        finding = _make_finding()
        result = finding.to_dict()
        assert isinstance(result, dict)

    def test_finding_to_dict_contains_rule_id(self):
        """to_dict() includes rule_id."""
        finding = _make_finding()
        result = finding.to_dict()
        assert result["rule_id"] == "AZ-NET-001"

    def test_finding_optional_fields_default_to_none(self):
        """Optional fields default to None or empty."""
        finding = _make_finding()
        assert finding.scan_id is None
        assert finding.playbook is None
        assert finding.id is None

    def test_finding_metadata_defaults_to_empty_dict(self):
        """metadata defaults to empty dict."""
        finding = _make_finding()
        assert finding.metadata == {}

    def test_finding_cve_references_defaults_to_empty_list(self):
        """cve_references defaults to empty list."""
        finding = _make_finding()
        assert finding.cve_references == []

    def test_finding_exploit_available_defaults_to_false(self):
        """exploit_available defaults to False."""
        finding = _make_finding()
        assert finding.exploit_available is False


# ---------------------------------------------------------------------------
# Score calculation tests
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Score calculation tests — call real get_score() via mock cursor
# ---------------------------------------------------------------------------


class TestScoreCalculation:
    """Tests for DatabaseManager.get_score() SQL aggregation and floor logic."""

    def _make_db_with_score(self, fetchone_value):
        db = DatabaseManager(dsn="postgresql://test:test@localhost/test")
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_cursor.fetchall.return_value = fetchone_value
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.closed = False
        db.conn = mock_conn
        db._get_conn = MagicMock(return_value=mock_conn)
        return db

    def test_get_score_returns_100_with_no_findings(self):
        """get_score() returns 100 when there are no findings."""
        db = self._make_db_with_score([])
        assert db.get_score() == 100

    def test_get_score_deducts_high_severity(self):
        """get_score() deducts 10 per HIGH finding via SQL aggregation."""
        db = self._make_db_with_score([("HIGH", 2)])
        assert db.get_score() == 80

    def test_get_score_deducts_multiple_severities(self):
        """get_score() deducts correct amounts for mixed severities."""
        db = self._make_db_with_score([("HIGH", 1), ("MEDIUM", 2)])
        assert db.get_score() == 80

    def test_get_score_floors_at_zero(self):
        """get_score() floors at 0 — never returns negative."""
        db = self._make_db_with_score([("HIGH", 20)])
        assert db.get_score() == 0

    def test_get_score_returns_integer(self):
        """get_score() returns an integer."""
        db = self._make_db_with_score([("LOW", 1)])
        assert isinstance(db.get_score(), int)

    def test_get_score_calls_execute(self):
        """get_score() calls cursor.execute — SQL actually runs."""
        db = self._make_db_with_score([])
        db.get_score()
        db.conn.cursor().__enter__().execute.assert_called_once()

    def test_severity_weights_high_outweighs_medium(self):
        assert SEVERITY_WEIGHTS["HIGH"] > SEVERITY_WEIGHTS["MEDIUM"]

    def test_severity_weights_medium_outweighs_low(self):
        assert SEVERITY_WEIGHTS["MEDIUM"] > SEVERITY_WEIGHTS["LOW"]

    def test_severity_weights_info_is_zero(self):
        assert SEVERITY_WEIGHTS.get("INFO", 0) == 0
