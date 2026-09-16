"""Prioritization API severity-contract regressions."""

from unittest.mock import MagicMock, patch

import api.routes.prioritization as prioritization_route


class _PrioritizationCursor:
    def __init__(self):
        self.query = ""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, query, params=None):
        self.query = query

    def fetchone(self):
        return {"scan_id": "00000000-0000-0000-0000-000000000000"}

    def fetchall(self):
        if "GROUP BY rule_id" in self.query:
            return [
                {
                    "rule_id": "AZ-SC-005",
                    "rule_name": "Unsigned production image",
                    "severity": "CRITICAL",
                    "category": "Supply Chain",
                    "remediation": "Sign and verify the image.",
                    "affected_count": 1,
                    "resource_name": "prod-acr",
                }
            ]
        return [{"severity": "CRITICAL", "count": 3}]


def test_critical_prioritization_uses_contract_risk_weight_and_counts(client, auth_headers):
    cursor = _PrioritizationCursor()
    connection = MagicMock()
    connection.cursor.return_value = cursor
    db = MagicMock()
    db._get_conn.return_value = connection

    with patch.object(prioritization_route, "_get_db", return_value=db):
        response = client.get("/api/prioritization", headers=auth_headers)

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["matrix"][0]["risk"] == 10
    assert payload["rankings"][0]["score"] == 20
    assert payload["rankings"][0]["impact"] == "CRITICAL"
    assert payload["action_items"][0]["impact"] == "CRITICAL"
    assert payload["summary"]["criticalFindings"] == 3
    assert payload["summary"]["highRiskFindings"] == 0
