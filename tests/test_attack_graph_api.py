"""Unit tests for the attack graph API routes."""

import time
from unittest.mock import MagicMock, patch

import pytest

_TENANT = "00000000-0000-0000-0000-000000000001"


@pytest.fixture()
def tenant_auth_headers(app):
    """Admin JWT headers with X-Tenant-Id for shared-secret mode tests."""
    import jwt

    secret = app.config["JWT_SECRET"]
    payload = {
        "sub": "test-user",
        "role": "admin",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Tenant-Id": _TENANT,
    }


def _mock_conn(rows_sequence=None):
    """Return a mock psycopg2 connection returning preset rows per cursor call."""
    rows_sequence = list(rows_sequence or [])
    conn = MagicMock()
    conn.autocommit = True
    call_idx = [0]

    def make_cursor(*args, **kwargs):
        cur = MagicMock()
        cur.__enter__ = lambda s: s
        cur.__exit__ = MagicMock(return_value=False)
        idx = call_idx[0]
        call_idx[0] += 1
        rows = rows_sequence[idx] if idx < len(rows_sequence) else []
        cur.fetchall.return_value = rows
        cur.fetchone.return_value = rows[0] if rows else None
        return cur

    conn.cursor.side_effect = make_cursor
    return conn


def test_get_attack_graph_returns_empty_nodes_and_edges(client, tenant_auth_headers):
    conn = _mock_conn([[]])
    with patch("api.routes.attack_graph.psycopg2.connect", return_value=conn):
        with patch.dict("os.environ", {"DATABASE_URL": "postgresql://fake/db"}):
            resp = client.get("/api/v1/attack-graph", headers=tenant_auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert "nodes" in data
    assert "edges" in data


def test_get_attack_graph_viewer_cannot_supply_tenant_header(client, app):
    """Viewer-role tokens must not use X-Tenant-Id header (admin-only)."""
    import jwt

    secret = app.config["JWT_SECRET"]
    payload = {
        "sub": "viewer-user",
        "role": "viewer",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Tenant-Id": _TENANT,
    }
    resp = client.get("/api/v1/attack-graph", headers=headers)
    assert resp.status_code == 403


def test_list_attack_paths_missing_scan_id_returns_400(client, tenant_auth_headers):
    resp = client.get("/api/v1/attack-paths", headers=tenant_auth_headers)
    assert resp.status_code == 400
    assert b"scan_id" in resp.data


def test_list_attack_paths_invalid_uuid_returns_400(client, tenant_auth_headers):
    resp = client.get("/api/v1/attack-paths?scan_id=not-a-uuid", headers=tenant_auth_headers)
    assert resp.status_code == 400


def test_get_attack_path_invalid_uuid_returns_400(client, tenant_auth_headers):
    resp = client.get("/api/v1/attack-paths/not-a-uuid", headers=tenant_auth_headers)
    assert resp.status_code == 400


def test_get_attack_path_not_found_returns_404(client, tenant_auth_headers):
    valid_uuid = "00000000-0000-0000-0000-000000000002"
    conn = _mock_conn([[]])
    with patch("api.routes.attack_graph.psycopg2.connect", return_value=conn):
        with patch.dict("os.environ", {"DATABASE_URL": "postgresql://fake/db"}):
            resp = client.get(f"/api/v1/attack-paths/{valid_uuid}", headers=tenant_auth_headers)
    assert resp.status_code == 404


@pytest.mark.parametrize("limit", ["abc", "", "1.5", "0", "-1"])
@pytest.mark.parametrize(
    "endpoint", ["/api/v1/attack-graph", "/api/v1/attack-paths?scan_id=00000000-0000-0000-0000-000000000002"]
)
def test_malformed_limit_returns_400(client, tenant_auth_headers, endpoint, limit):
    separator = "&" if "?" in endpoint else "?"
    response = client.get(f"{endpoint}{separator}limit={limit}", headers=tenant_auth_headers)
    assert response.status_code == 400


def test_verified_viewer_tenant_cannot_be_overridden_by_header_or_query(client, app):
    import jwt

    token = jwt.encode(
        {"sub": "viewer", "role": "viewer", "tid": _TENANT, "exp": int(time.time()) + 60},
        app.config["JWT_SECRET"],
        algorithm="HS256",
    )
    foreign = "00000000-0000-0000-0000-000000000099"
    conn = MagicMock()
    cursor = conn.cursor.return_value.__enter__.return_value
    cursor.fetchall.return_value = []
    db = MagicMock()
    db.conn = conn
    with patch("api.routes.attack_graph._get_db", return_value=db):
        response = client.get(
            f"/api/v1/attack-graph?tenant_id={foreign}",
            headers={"Authorization": f"Bearer {token}", "X-Tenant-Id": foreign},
        )
    assert response.status_code == 200
    assert cursor.execute.call_args[0][1]["tenant_id"] == _TENANT
