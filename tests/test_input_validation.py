"""Security regression tests for public input boundaries tracked by #201."""

from unittest.mock import MagicMock, patch

import pytest

import api.routes.findings as findings_route
import api.routes.compliance as compliance_route
import api.routes.scans as scans_route
from api.validation import MAX_API_KEY_LENGTH, MAX_FINDINGS, MAX_QUESTION_LENGTH, VALIDATION_ERROR_MESSAGE

_SCAN_ID = "00000000-0000-0000-0000-000000000001"
_SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000002"


@pytest.mark.parametrize(
    "path",
    [
        "/api/scans/not-a-uuid",
        "/api/scans/not-a-uuid/enrich",
    ],
)
def test_scan_paths_reject_non_uuid_before_database(client, auth_headers, path):
    with patch.object(scans_route, "_get_db") as get_db:
        response = (
            client.get(path, headers=auth_headers)
            if not path.endswith("/enrich")
            else client.post(path, headers=auth_headers)
        )
    assert response.status_code == 400
    get_db.assert_not_called()


def test_trigger_rejects_non_object_json(client, auth_headers):
    with patch.object(scans_route, "_get_db") as get_db:
        response = client.post("/api/scans/trigger", json=[_SUBSCRIPTION_ID], headers=auth_headers)
    assert response.status_code == 400
    get_db.assert_not_called()


def test_trigger_rejects_unknown_json_field(client, auth_headers):
    with patch.object(scans_route, "_get_db") as get_db:
        response = client.post(
            "/api/scans/trigger",
            json={"subscription_id": _SUBSCRIPTION_ID, "command": "ignored-before-fix"},
            headers=auth_headers,
        )
    assert response.status_code == 400
    get_db.assert_not_called()


def test_trigger_rejects_malformed_subscription_id(client, auth_headers):
    with patch.object(scans_route, "_get_db") as get_db:
        response = client.post("/api/scans/trigger", json={"subscription_id": "../../etc/passwd"}, headers=auth_headers)
    assert response.status_code == 400
    assert response.get_json() == {"error": VALIDATION_ERROR_MESSAGE}
    assert "../../etc/passwd" not in response.get_data(as_text=True)
    get_db.assert_not_called()


def test_trigger_accepts_canonical_subscription_uuid(client, auth_headers):
    db = MagicMock()
    with patch.object(scans_route, "_get_db", return_value=db):
        response = client.post("/api/scans/trigger", json={"subscription_id": _SUBSCRIPTION_ID}, headers=auth_headers)
    assert response.status_code == 202
    assert db.create_pending_scan.call_args.args[1] == _SUBSCRIPTION_ID


@pytest.mark.parametrize(
    "query",
    [
        "severity=INVALID",
        "category=Unknown",
        "rule_id=../../secret",
        "scan_id=not-a-uuid",
        "limit=1000000",
        "severity=HIGH&severity=LOW",
    ],
)
def test_finding_filters_reject_values_outside_contract(client, auth_headers, query):
    with patch.object(findings_route, "_get_db") as get_db:
        response = client.get(f"/api/findings?{query}", headers=auth_headers)
    assert response.status_code == 400
    get_db.assert_not_called()


@pytest.mark.parametrize("category", ["Network", "network", "NETWORK"])
def test_finding_filters_are_normalised_before_database(client, auth_headers, category):
    db = MagicMock()
    db.get_findings.return_value = []
    with patch.object(findings_route, "_get_db", return_value=db):
        response = client.get(
            f"/api/findings?severity=high&category={category}&rule_id=az-net-001&scan_id={_SCAN_ID}",
            headers=auth_headers,
        )
    assert response.status_code == 200
    db.get_findings.assert_called_once_with(
        {"severity": "HIGH", "category": "Network", "rule_id": "AZ-NET-001", "scan_id": _SCAN_ID}
    )


def test_compliance_framework_rejects_untrusted_value_without_reflection(client, auth_headers):
    supplied = "not-a-framework<script>"
    with patch.object(compliance_route, "_get_db") as get_db:
        response = client.get(f"/api/compliance/{supplied}", headers=auth_headers)
    assert response.status_code == 400
    assert response.get_json()["error"] == VALIDATION_ERROR_MESSAGE
    assert supplied not in response.get_data(as_text=True)
    get_db.assert_not_called()


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"provider": ["groq"], "api_key": "secret", "findings": [{}]},
        {"provider": "groq", "api_key": "secret", "findings": [{}], "unexpected": True},
        {"provider": "groq", "api_key": "x" * (MAX_API_KEY_LENGTH + 1), "findings": [{}]},
        {"provider": "groq", "api_key": "secret", "model": "../model", "findings": [{}]},
        {"provider": "groq", "api_key": "secret", "findings": ["not-an-object"]},
        {"provider": "groq", "api_key": "secret", "findings": [{"severity": "urgent"}]},
        {"provider": "groq", "api_key": "secret", "findings": [{}] * (MAX_FINDINGS + 1)},
        {
            "provider": "groq",
            "api_key": "secret",
            "findings": [{}],
            "question": "x" * (MAX_QUESTION_LENGTH + 1),
        },
    ],
)
def test_ai_insights_rejects_invalid_shapes_and_limits(client, auth_headers, payload):
    response = client.post("/api/ai/insights", json=payload, headers=auth_headers)
    assert response.status_code == 400


def test_invalid_request_id_is_replaced(client):
    supplied = "contains spaces " + ("x" * 200)
    response = client.get("/health", headers={"X-Request-ID": supplied})
    returned = response.headers["X-Request-ID"]
    assert returned != supplied
    assert len(returned) == 36


def test_safe_request_id_is_preserved(client):
    response = client.get("/health", headers={"X-Request-ID": "client-request_123"})
    assert response.headers["X-Request-ID"] == "client-request_123"


def test_oversized_authorization_header_is_rejected(client):
    response = client.get("/api/findings", headers={"Authorization": "Bearer " + ("x" * 9000)})
    assert response.status_code == 401


@pytest.mark.parametrize(
    ("supplied", "expected"),
    [("critical", "CRITICAL"), ("INFORMATIONAL", "INFO")],
)
def test_finding_severity_filters_are_canonicalized(client, auth_headers, supplied, expected):
    db = MagicMock()
    db.get_findings.return_value = []
    with patch.object(findings_route, "_get_db", return_value=db):
        response = client.get(f"/api/findings?severity={supplied}", headers=auth_headers)

    assert response.status_code == 200
    db.get_findings.assert_called_once_with({"severity": expected})
