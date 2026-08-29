"""Tests for the OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS allowlist on
POST /api/scans/trigger (issue #294's single-tenant containment boundary).

A valid operator/admin token alone doesn't say which Azure subscription its
holder is entitled to scan - without this allowlist, any authenticated
write-capable token can trigger a scan against an arbitrary subscription_id.
"""

from unittest.mock import MagicMock, patch

AUTHORIZED = "11111111-1111-1111-1111-111111111111"
UNAUTHORIZED = "22222222-2222-2222-2222-222222222222"


def _trigger(client, auth_headers, subscription_id, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://ci:ci@localhost/ci_db")
    database = MagicMock()
    database.admit_scan.return_value = (
        {"scan_id": "test-scan", "status": "pending"},
        True,
    )
    with patch("api.routes.scans.DatabaseManager", return_value=database):
        return client.post(
            "/api/scans/trigger",
            json={"subscription_id": subscription_id},
            headers=auth_headers,
        )


def test_unset_allowlist_accepts_any_subscription(client, auth_headers, monkeypatch):
    """Unset (the default) must preserve today's behavior - no allowlist
    configured means no deployment is unexpectedly broken by this change."""
    monkeypatch.delenv("OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS", raising=False)

    resp = _trigger(client, auth_headers, UNAUTHORIZED, monkeypatch)

    assert resp.status_code == 202


def test_allowlisted_subscription_is_accepted(client, auth_headers, monkeypatch):
    other = "33333333-3333-3333-3333-333333333333"
    monkeypatch.setenv("OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS", f"{AUTHORIZED},{other}")

    resp = _trigger(client, auth_headers, AUTHORIZED, monkeypatch)

    assert resp.status_code == 202


def test_subscription_outside_allowlist_is_rejected(client, auth_headers, monkeypatch):
    monkeypatch.setenv("OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS", AUTHORIZED)

    resp = _trigger(client, auth_headers, UNAUTHORIZED, monkeypatch)

    assert resp.status_code == 403
    assert "not authorized" in resp.get_json()["error"]


def test_allowlist_comparison_is_case_insensitive(client, auth_headers, monkeypatch):
    monkeypatch.setenv("OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS", AUTHORIZED.upper())

    resp = _trigger(client, auth_headers, AUTHORIZED, monkeypatch)

    assert resp.status_code == 202


def test_allowlist_ignores_blank_entries_and_whitespace(client, auth_headers, monkeypatch):
    monkeypatch.setenv("OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS", f" {AUTHORIZED} ,, ")

    resp = _trigger(client, auth_headers, AUTHORIZED, monkeypatch)

    assert resp.status_code == 202


def test_startup_warns_when_allowlist_is_unset(monkeypatch, caplog):
    import logging

    monkeypatch.delenv("OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS", raising=False)
    from api.app import create_app

    with caplog.at_level(logging.WARNING):
        create_app()

    assert any("OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS" in record.getMessage() for record in caplog.records)


def test_startup_does_not_warn_when_allowlist_is_set(monkeypatch, caplog):
    import logging

    monkeypatch.setenv("OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS", AUTHORIZED)
    from api.app import create_app

    with caplog.at_level(logging.WARNING):
        create_app()

    assert not any("OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS" in record.message for record in caplog.records)
