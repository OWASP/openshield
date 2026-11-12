"""Shared pytest fixtures for the OpenShield test suite."""

import secrets
import time

import pytest

from tests.helpers.mock_azure import MockAzureClient

collect_ignore = ["smoke_test.py"]

_TEST_JWT_SECRET = secrets.token_urlsafe(32)


@pytest.fixture
def app():
    from api.app import create_app

    application = create_app()
    application.config["TESTING"] = True
    application.config["JWT_SECRET"] = _TEST_JWT_SECRET

    # In tests the verifier runs in shared_secret mode which always sets
    # tenant=None.  Add a before_request hook that upgrades the principal to
    # include a synthetic test tenant so agent-route tests can pass the
    # empty-tenant guard without needing real OIDC configuration.
    from flask import g as _g

    @application.before_request
    def _inject_test_tenant():
        # Only patch if g.user is already set (i.e., auth passed) and tenant is None
        try:
            if _g.user.get("tenant") is None:
                _g.user = {**_g.user, "tenant": "test-tenant-001"}
        except AttributeError:
            pass

    return application


@pytest.fixture
def app_no_tenant_inject():
    """App fixture without the synthetic tenant injection hook.

    Used by tests that specifically validate the empty-tenant 403 guard.
    """
    from api.app import create_app

    application = create_app()
    application.config["TESTING"] = True
    application.config["JWT_SECRET"] = _TEST_JWT_SECRET
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_headers():
    import jwt

    payload = {
        "sub": "test-user",
        "role": "admin",
        "tenant": "test-tenant-001",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    token = jwt.encode(payload, _TEST_JWT_SECRET, algorithm="HS256")
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


@pytest.fixture
def mock_azure() -> MockAzureClient:
    """Return a clean MockAzureClient with no resources configured."""
    return MockAzureClient()


@pytest.fixture
def subscription_id() -> str:
    """Return a fake Azure subscription ID for use in scan() calls."""
    return "00000000-0000-0000-0000-000000000001"
