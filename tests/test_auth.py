"""Tests for JWT authentication middleware — production and demo modes."""

import secrets
import time

import jwt
import pytest

_SECRET = secrets.token_urlsafe(32)


def _make_token(role="admin", include_exp=True, include_role=True) -> str:
    payload = {"sub": "test-user", "iat": int(time.time())}
    if include_role:
        payload["role"] = role
    if include_exp:
        payload["exp"] = int(time.time()) + 3600
    return jwt.encode(payload, _SECRET, algorithm="HS256")


@pytest.fixture
def prod_client(monkeypatch):
    """Flask test client with default (JWT-required) auth mode."""
    monkeypatch.delenv("OPENSHIELD_PUBLIC_DEMO", raising=False)
    from api.app import create_app

    app = create_app()
    app.config["TESTING"] = True
    app.config["JWT_SECRET"] = _SECRET
    return app.test_client()


@pytest.fixture
def demo_client(monkeypatch):
    """Flask test client with OPENSHIELD_PUBLIC_DEMO=true."""
    monkeypatch.setenv("OPENSHIELD_PUBLIC_DEMO", "true")
    from api.app import create_app

    app = create_app()
    app.config["TESTING"] = True
    app.config["JWT_SECRET"] = _SECRET
    return app.test_client()


# ── /health is always public ─────────────────────────────────────────────────
def test_health_public_in_default_mode(prod_client):
    assert prod_client.get("/health").status_code == 200


def test_health_public_in_demo_mode(demo_client):
    assert demo_client.get("/health").status_code == 200


# ── Default mode: GET /api/* requires JWT ────────────────────────────────────
def test_api_get_requires_jwt_no_header(prod_client):
    assert prod_client.get("/api/findings").status_code == 401


def test_api_get_requires_jwt_bad_token(prod_client):
    resp = prod_client.get("/api/findings", headers={"Authorization": "Bearer not-a-real-token"})
    assert resp.status_code == 401


def test_api_get_passes_auth_with_valid_jwt(prod_client):
    headers = {"Authorization": f"Bearer {_make_token()}"}
    resp = prod_client.get("/api/findings", headers=headers)
    assert resp.status_code != 401


def test_api_post_requires_jwt_in_default_mode(prod_client):
    resp = prod_client.post("/api/scans/trigger", json={})
    assert resp.status_code == 401


# ── Demo mode: GET /api/* is public, POST still requires JWT ─────────────────
def test_demo_get_allowed_without_jwt(demo_client):
    resp = demo_client.get("/api/findings")
    assert resp.status_code != 401


def test_demo_post_still_requires_jwt(demo_client):
    resp = demo_client.post("/api/scans/trigger", json={})
    assert resp.status_code == 401


def test_demo_score_allowed_without_jwt(demo_client):
    resp = demo_client.get("/api/score")
    assert resp.status_code != 401


# ── Required claims: every accepted token must carry exp and a known role ───
# (issue #294 - the previously-embeddable demo token had neither enforced)


def test_token_without_exp_is_rejected(prod_client):
    headers = {"Authorization": f"Bearer {_make_token(include_exp=False)}"}
    resp = prod_client.get("/api/findings", headers=headers)
    assert resp.status_code == 401


def test_token_without_role_is_rejected(prod_client):
    headers = {"Authorization": f"Bearer {_make_token(include_role=False)}"}
    resp = prod_client.get("/api/findings", headers=headers)
    assert resp.status_code == 401


def test_token_with_unrecognized_role_is_rejected(prod_client):
    headers = {"Authorization": f"Bearer {_make_token(role='superuser')}"}
    resp = prod_client.get("/api/findings", headers=headers)
    assert resp.status_code == 401


# ── viewer is read-only; operator/admin may write ────────────────────────────


def test_viewer_role_can_read(prod_client):
    headers = {"Authorization": f"Bearer {_make_token(role='viewer')}"}
    resp = prod_client.get("/api/findings", headers=headers)
    assert resp.status_code != 401
    assert resp.status_code != 403


def test_viewer_role_cannot_write(prod_client):
    headers = {"Authorization": f"Bearer {_make_token(role='viewer')}"}
    resp = prod_client.post("/api/scans/trigger", json={}, headers=headers)
    assert resp.status_code == 403


def test_viewer_role_cannot_write_even_in_demo_mode(demo_client):
    """public_demo only ever widens *read* access - the write-role gate
    must hold regardless of it."""
    headers = {"Authorization": f"Bearer {_make_token(role='viewer')}"}
    resp = demo_client.post("/api/scans/trigger", json={}, headers=headers)
    assert resp.status_code == 403


def test_operator_role_can_write(prod_client):
    headers = {"Authorization": f"Bearer {_make_token(role='operator')}"}
    resp = prod_client.post("/api/scans/trigger", json={}, headers=headers)
    # Fails past auth on missing DATABASE_URL/subscription_id in this test
    # environment - the point here is only that role enforcement itself
    # doesn't block it (a 403 would mean the role gate rejected it).
    assert resp.status_code != 401
    assert resp.status_code != 403


def test_admin_role_can_write(prod_client):
    headers = {"Authorization": f"Bearer {_make_token(role='admin')}"}
    resp = prod_client.post("/api/scans/trigger", json={}, headers=headers)
    assert resp.status_code != 401
    assert resp.status_code != 403
