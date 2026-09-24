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
            resp = client.get("/api/attack-graph", headers=tenant_auth_headers)
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
    resp = client.get("/api/attack-graph", headers=headers)
    assert resp.status_code == 400


def test_list_attack_paths_missing_scan_id_returns_400(client, tenant_auth_headers):
    resp = client.get("/api/attack-paths", headers=tenant_auth_headers)
    assert resp.status_code == 400
    assert b"scan_id" in resp.data


def test_list_attack_paths_invalid_uuid_returns_400(client, tenant_auth_headers):
    resp = client.get("/api/attack-paths?scan_id=not-a-uuid", headers=tenant_auth_headers)
    assert resp.status_code == 400


def test_get_attack_path_invalid_uuid_returns_400(client, tenant_auth_headers):
    resp = client.get("/api/attack-paths/not-a-uuid", headers=tenant_auth_headers)
    assert resp.status_code == 400


def test_get_attack_path_not_found_returns_404(client, tenant_auth_headers):
    valid_uuid = "00000000-0000-0000-0000-000000000002"
    conn = _mock_conn([[]])
    with patch("api.routes.attack_graph.psycopg2.connect", return_value=conn):
        with patch.dict("os.environ", {"DATABASE_URL": "postgresql://fake/db"}):
            resp = client.get(f"/api/attack-paths/{valid_uuid}", headers=tenant_auth_headers)
    assert resp.status_code == 404
