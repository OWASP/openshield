"""OIDC bearer-token verification (issue #294).

Tokens are signed with a throwaway RSA key and served through a stub JWKS
client, so every rejection path is exercised without network access.
"""

import secrets
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from api import auth

ISSUER = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"
AUDIENCE = "api://openshield"
TENANT = "11111111-1111-1111-1111-111111111111"
OTHER_TENANT = "22222222-2222-2222-2222-222222222222"
JWKS_URL = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/discovery/v2.0/keys"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class _SigningKey:
    def __init__(self, key):
        self.key = key


class _StubJwks:
    """Mimics PyJWKClient.get_signing_key_from_jwt for a single known key."""

    def __init__(self, error=None):
        self.error = error

    def get_signing_key_from_jwt(self, token):
        if self.error is not None:
            raise self.error
        if jwt.get_unverified_header(token).get("kid") != "test-key":
            raise jwt.PyJWKClientError("Unable to find a signing key that matches")
        return _SigningKey(_KEY.public_key())


def _env(**overrides):
    env = {
        "OPENSHIELD_AUTH_MODE": "oidc",
        "OIDC_ISSUER": ISSUER,
        "OIDC_AUDIENCE": AUDIENCE,
        "OIDC_JWKS_URL": JWKS_URL,
        "OIDC_ALLOWED_TENANTS": TENANT,
    }
    env.update(overrides)
    return {k: v for k, v in env.items() if v is not None}


def _claims(**overrides):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-object-id",
        "tid": TENANT,
        "iat": now,
        "exp": now + 3600,
        "roles": ["OpenShield.Viewer"],
    }
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


def _token(claims=None, key=_KEY, kid="test-key", algorithm="RS256"):
    return jwt.encode(claims or _claims(), key, algorithm=algorithm, headers={"kid": kid})


def _verifier(jwks=None, **env_overrides):
    env = _env(**env_overrides)
    return auth.TokenVerifier(
        "oidc", lambda: "unused", oidc=auth.load_oidc_settings(env), jwks_client=jwks or _StubJwks(), env=env
    )


def _rejected(verifier, token):
    with pytest.raises(auth.TokenRejected) as info:
        verifier.verify(token)
    return info.value


# ── accepted principal ──────────────────────────────────────────────────────


def test_valid_token_yields_principal_from_idp_claims():
    principal = _verifier().verify(_token())
    assert principal == {
        "sub": "user-object-id",
        "role": "viewer",
        "tenant": TENANT,
        "issuer": ISSUER,
        "auth_mode": "oidc",
    }


def test_highest_assigned_app_role_wins():
    token = _token(_claims(roles=["OpenShield.Viewer", "OpenShield.Admin", "OpenShield.Operator"]))
    assert _verifier().verify(token)["role"] == "admin"


def test_custom_role_map_and_claim():
    verifier = _verifier(OIDC_ROLE_CLAIM="groups", OIDC_ROLE_MAP="sec-ops=operator")
    assert verifier.verify(_token(_claims(roles=None, groups=["sec-ops"])))["role"] == "operator"


# ── rejected tokens ─────────────────────────────────────────────────────────


def test_expired_token_is_rejected():
    now = int(time.time())
    error = _rejected(_verifier(), _token(_claims(iat=now - 7200, exp=now - 3600)))
    assert (error.status, error.message) == (401, "Token has expired")


def test_wrong_issuer_is_rejected():
    error = _rejected(_verifier(), _token(_claims(iss="https://evil.example/v2.0")))
    assert (error.status, error.message) == (401, "Invalid token")


def test_wrong_audience_is_rejected():
    assert _rejected(_verifier(), _token(_claims(aud="api://someone-else"))).status == 401


@pytest.mark.parametrize("claim", ["exp", "iat", "sub", "iss", "aud"])
def test_missing_required_claim_is_rejected(claim):
    assert _rejected(_verifier(), _token(_claims(**{claim: None}))).status == 401


def test_tenant_outside_allowlist_is_rejected():
    assert _rejected(_verifier(), _token(_claims(tid=OTHER_TENANT))).status == 401


def test_missing_tenant_is_rejected_when_allowlist_is_set():
    assert _rejected(_verifier(), _token(_claims(tid=None))).status == 401


def test_tenant_allowlist_is_optional():
    assert _verifier(OIDC_ALLOWED_TENANTS=None).verify(_token(_claims(tid=OTHER_TENANT)))["tenant"] == OTHER_TENANT


def test_identity_without_openshield_role_is_forbidden():
    error = _rejected(_verifier(), _token(_claims(roles=["SomeOtherApp.Admin"])))
    assert error.status == 403


def test_self_asserted_role_claim_is_ignored():
    """A shared-secret style 'role' claim must not grant access in OIDC mode."""
    error = _rejected(_verifier(), _token(_claims(roles=None, role="admin")))
    assert error.status == 403


def test_token_signed_by_unknown_key_is_rejected():
    assert _rejected(_verifier(), _token(key=_OTHER_KEY)).status == 401


def test_unknown_kid_is_rejected():
    assert _rejected(_verifier(), _token(kid="rotated-away")).status == 401


def test_hs256_token_cannot_pass_as_idp_token():
    """Algorithm confusion: an HMAC token must be refused before key lookup."""
    token = jwt.encode(_claims(), "a-shared-secret-that-is-long-enough", algorithm="HS256", headers={"kid": "test-key"})
    assert _rejected(_verifier(), token).status == 401


def test_unsigned_token_is_rejected():
    token = jwt.encode(_claims(), None, algorithm="none", headers={"kid": "test-key"})
    assert _rejected(_verifier(), token).status == 401


def test_garbage_token_is_rejected():
    assert _rejected(_verifier(), "not.a.jwt").status == 401


def test_unreachable_jwks_fails_closed_with_503():
    jwks = _StubJwks(error=jwt.PyJWKClientConnectionError("timed out"))
    error = _rejected(_verifier(jwks=jwks), _token())
    assert (error.status, error.message) == (503, "Identity provider unavailable")


# ── configuration fails closed ──────────────────────────────────────────────


@pytest.mark.parametrize("missing", ["OIDC_ISSUER", "OIDC_AUDIENCE", "OIDC_JWKS_URL"])
def test_oidc_mode_requires_issuer_audience_and_jwks(missing):
    with pytest.raises(auth.AuthConfigError, match=missing):
        auth.build_verifier(lambda: "x", env=_env(**{missing: None}))


def test_jwks_url_must_be_https():
    with pytest.raises(auth.AuthConfigError, match="https"):
        auth.load_oidc_settings(_env(OIDC_JWKS_URL="http://login.example/keys"))


def test_symmetric_algorithms_are_refused_in_oidc_mode():
    with pytest.raises(auth.AuthConfigError, match="HS256"):
        auth.load_oidc_settings(_env(OIDC_ALGORITHMS="RS256,HS256"))


def test_invalid_role_map_is_refused():
    with pytest.raises(auth.AuthConfigError):
        auth.load_oidc_settings(_env(OIDC_ROLE_MAP="OpenShield.Root=superuser"))


def test_unknown_auth_mode_is_refused():
    with pytest.raises(auth.AuthConfigError):
        auth.load_auth_mode({"OPENSHIELD_AUTH_MODE": "anonymous"})


def test_app_refuses_to_start_with_incomplete_oidc_config(monkeypatch):
    monkeypatch.setenv("OPENSHIELD_AUTH_MODE", "oidc")
    monkeypatch.delenv("OIDC_ISSUER", raising=False)
    from api.app import create_app

    with pytest.raises(auth.AuthConfigError):
        create_app()


# ── shared-secret mode hardening ────────────────────────────────────────────

_SECRET = secrets.token_urlsafe(32)


def _hs_token(**overrides):
    now = int(time.time())
    claims = {"sub": "svc", "role": "operator", "iat": now, "exp": now + 600}
    claims.update(overrides)
    return jwt.encode({k: v for k, v in claims.items() if v is not None}, _SECRET, algorithm="HS256")


def test_shared_secret_token_without_subject_is_rejected():
    verifier = auth.TokenVerifier("shared_secret", lambda: _SECRET, env={})
    assert _rejected(verifier, _hs_token(sub=None)).status == 401


def test_shared_secret_validates_issuer_and_audience_when_configured():
    env = {"JWT_ISSUER": "openshield-ci", "JWT_AUDIENCE": "openshield-api"}
    verifier = auth.TokenVerifier("shared_secret", lambda: _SECRET, env=env)
    assert verifier.verify(_hs_token(iss="openshield-ci", aud="openshield-api"))["role"] == "operator"
    assert _rejected(verifier, _hs_token(iss="someone-else", aud="openshield-api")).status == 401
    assert _rejected(verifier, _hs_token(iss="openshield-ci")).status == 401


def test_shared_secret_rejects_rs256_token():
    verifier = auth.TokenVerifier("shared_secret", lambda: _SECRET, env={})
    token = jwt.encode({"sub": "x", "role": "admin", "exp": int(time.time()) + 60}, _KEY, algorithm="RS256")
    assert _rejected(verifier, token).status == 401


# ── middleware integration ──────────────────────────────────────────────────


@pytest.fixture
def oidc_client(monkeypatch):
    for key, value in _env().items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("OPENSHIELD_PUBLIC_DEMO", raising=False)
    monkeypatch.setattr(jwt, "PyJWKClient", lambda *args, **kwargs: _StubJwks())
    from api.app import create_app

    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_oidc_viewer_can_read_but_not_write(oidc_client):
    headers = {"Authorization": f"Bearer {_token()}"}
    read = oidc_client.get("/api/findings", headers=headers)
    assert read.status_code not in (401, 403)
    write = oidc_client.post("/api/scans/trigger", json={}, headers=headers)
    assert write.status_code == 403


def test_oidc_operator_passes_write_gate(oidc_client):
    headers = {"Authorization": f"Bearer {_token(_claims(roles=['OpenShield.Operator']))}"}
    resp = oidc_client.post("/api/scans/trigger", json={}, headers=headers)
    assert resp.status_code not in (401, 403)


def test_oidc_mode_rejects_shared_secret_tokens_at_the_api(oidc_client, auth_headers):
    """The conftest admin token is HS256 - it must not work once OIDC is on."""
    assert oidc_client.get("/api/findings", headers=auth_headers).status_code == 401


def test_oidc_wrong_tenant_is_rejected_at_the_api(oidc_client):
    headers = {"Authorization": f"Bearer {_token(_claims(tid=OTHER_TENANT))}"}
    resp = oidc_client.get("/api/findings", headers=headers)
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Invalid token"
