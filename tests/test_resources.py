"""Resource API severity-contract regressions."""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import api.routes.resources as resources_route


class _ResourceCursor:
    def __init__(self):
        self.query = ""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, query, params=None):
        self.query = query

    def fetchone(self):
        return {
            "scan_id": "00000000-0000-0000-0000-000000000000",
            "started_at": datetime(2026, 8, 21, tzinfo=timezone.utc),
        }

    def fetchall(self):
        return [
            {
                "resource_id": (
                    "/subscriptions/00000000-0000-0000-0000-000000000001/"
                    "resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/prod-kv"
                ),
                "resource_name": "prod-kv",
                "resource_type": "Microsoft.KeyVault/vaults",
                "category": "KeyVault",
                "discovered_at": datetime(2026, 8, 21, tzinfo=timezone.utc),
                "risk_rank": 4,
            }
        ]


def test_critical_only_resource_is_not_reported_as_none(client, auth_headers):
    cursor = _ResourceCursor()
    connection = MagicMock()
    connection.cursor.return_value = cursor
    db = MagicMock()
    db._get_conn.return_value = connection

    with patch.object(resources_route, "_get_db", return_value=db):
        response = client.get("/api/resources", headers=auth_headers)

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["resources"][0]["risk"] == "CRITICAL"
    assert payload["summary"]["by_risk_level"]["CRITICAL"] == 1
    assert payload["summary"]["by_risk_level"]["NONE"] == 0
    assert "WHEN 'CRITICAL' THEN 4" in cursor.query
