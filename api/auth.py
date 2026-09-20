"""Bearer-token verification for the OpenShield API (issue #294).

Two verification modes are supported, selected with ``OPENSHIELD_AUTH_MODE``:

``shared_secret`` (default)
    HS256 tokens signed with ``JWT_SECRET``. Intended for local development,
    CI smoke tests and service-to-service calls. Every token must carry
    ``exp``, ``sub`` and a known ``role``. ``JWT_ISSUER``/``JWT_AUDIENCE`` are
    validated when configured.

``oidc``
    Tokens issued by an enterprise identity provider (for example Microsoft
    Entra ID) and verified against the provider's JWKS. Issuer, audience,
    expiry, issued-at and subject are required; the tenant (``tid``) must be in
    ``OIDC_ALLOWED_TENANTS`` when that allowlist is set; and the caller's role
    comes from an IdP-assigned claim (app roles), never from anything the
    browser can choose.

Only asymmetric algorithms are accepted in ``oidc`` mode, so a token signed
with a shared secret (or ``alg: none``) can never pass as an IdP token.
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, Iterable, Mapping, Optional, Tuple

import jwt

logger = logging.getLogger(__name__)

SHARED_SECRET_MODE = "shared_secret"  # nosec B105 - mode name, not a credential
AUTH_MODE_OIDC = "oidc"
AUTH_MODES = (SHARED_SECRET_MODE, AUTH_MODE_OIDC)

KNOWN_ROLES = frozenset({"viewer", "operator", "admin"})
WRITE_ROLES = frozenset({"operator", "admin"})
_ROLE_PRIORITY = {"viewer": 0, "operator": 1, "admin": 2}

# Entra ID app-role values assigned to users/groups in the enterprise app.
DEFAULT_OIDC_ROLE_MAP = {
    "OpenShield.Viewer": "viewer",
    "OpenShield.Operator": "operator",
    "OpenShield.Admin": "admin",
}
_ASYMMETRIC_ALGORITHMS = frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"})
_DEFAULT_LEEWAY_SECONDS = 60
_JWKS_CACHE_SECONDS = 300


class AuthConfigError(RuntimeError):
    """Raised at startup when authentication is misconfigured."""


class TokenRejected(Exception):
    """A bearer token was not accepted; carries the HTTP status to return."""

    def __init__(self, message: str, status: int = 401) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


@dataclass(frozen=True)
class OidcSettings:
    """Validated OIDC verification settings."""

    issuer: str
    audience: str
    jwks_url: str
    allowed_tenants: FrozenSet[str] = frozenset()
    role_claim: str = "roles"
    role_map: Mapping[str, str] = field(default_factory=lambda: dict(DEFAULT_OIDC_ROLE_MAP))
    algorithms: Tuple[str, ...] = ("RS256",)
    leeway: int = _DEFAULT_LEEWAY_SECONDS


def _csv(value: Optional[str]) -> Tuple[str, ...]:
    return tuple(item.strip() for item in (value or "").split(",") if item.strip())


def load_auth_mode(env: Mapping[str, str] = os.environ) -> str:
    """Return the configured auth mode, rejecting unknown values."""
    mode = env.get("OPENSHIELD_AUTH_MODE", SHARED_SECRET_MODE).strip().lower() or SHARED_SECRET_MODE
    if mode not in AUTH_MODES:
        raise AuthConfigError(f"OPENSHIELD_AUTH_MODE must be one of {', '.join(AUTH_MODES)}; got {mode!r}")
    return mode


def _parse_role_map(raw: Optional[str]) -> Dict[str, str]:
    if not raw:
        return dict(DEFAULT_OIDC_ROLE_MAP)
    role_map: Dict[str, str] = {}
    for pair in _csv(raw):
        claim_value, sep, role = pair.partition("=")
        role = role.strip().lower()
        if not sep or not claim_value.strip() or role not in KNOWN_ROLES:
            raise AuthConfigError(
                f"OIDC_ROLE_MAP entries must look like '<claim value>=viewer|operator|admin'; got {pair!r}"
            )
        role_map[claim_value.strip()] = role
    return role_map


def load_oidc_settings(env: Mapping[str, str] = os.environ) -> OidcSettings:
    """Build OIDC settings from the environment, failing closed on gaps."""
    issuer = env.get("OIDC_ISSUER", "").strip()
    audience = env.get("OIDC_AUDIENCE", "").strip()
    jwks_url = env.get("OIDC_JWKS_URL", "").strip()
    missing = [
        name
        for name, value in (("OIDC_ISSUER", issuer), ("OIDC_AUDIENCE", audience), ("OIDC_JWKS_URL", jwks_url))
        if not value
    ]
    if missing:
        raise AuthConfigError(f"OPENSHIELD_AUTH_MODE=oidc requires {', '.join(missing)}")
    if not jwks_url.startswith("https://"):
        raise AuthConfigError("OIDC_JWKS_URL must use https")

    algorithms = _csv(env.get("OIDC_ALGORITHMS")) or ("RS256",)
    weak = [alg for alg in algorithms if alg not in _ASYMMETRIC_ALGORITHMS]
    if weak:
        raise AuthConfigError(f"OIDC_ALGORITHMS must be asymmetric; refusing {', '.join(weak)}")

    try:
        leeway = int(env.get("OIDC_CLOCK_SKEW_SECONDS", _DEFAULT_LEEWAY_SECONDS))
    except ValueError as exc:
        raise AuthConfigError("OIDC_CLOCK_SKEW_SECONDS must be an integer") from exc
    if not 0 <= leeway <= 300:
        raise AuthConfigError("OIDC_CLOCK_SKEW_SECONDS must be between 0 and 300")

    return OidcSettings(
        issuer=issuer,
        audience=audience,
        jwks_url=jwks_url,
        allowed_tenants=frozenset(tenant.lower() for tenant in _csv(env.get("OIDC_ALLOWED_TENANTS"))),
        role_claim=env.get("OIDC_ROLE_CLAIM", "roles").strip() or "roles",
        role_map=_parse_role_map(env.get("OIDC_ROLE_MAP")),
        algorithms=algorithms,
        leeway=leeway,
    )


def _highest_role(roles: Iterable[str]) -> Optional[str]:
    known = [role for role in roles if role in KNOWN_ROLES]
    return max(known, key=_ROLE_PRIORITY.__getitem__) if known else None


class TokenVerifier:
    """Verify bearer tokens and return the authenticated principal."""

    def __init__(
        self,
        mode: str,
        shared_secret: Callable[[], str],
        oidc: Optional[OidcSettings] = None,
        jwks_client: Optional[Any] = None,
        env: Mapping[str, str] = os.environ,
    ) -> None:
        if mode == AUTH_MODE_OIDC and oidc is None:
            raise AuthConfigError("oidc mode requires OidcSettings")
        self.mode = mode
        self._shared_secret = shared_secret
        self._oidc = oidc
        self._jwks_client = jwks_client
        self._jwt_issuer = env.get("JWT_ISSUER", "").strip() or None
        self._jwt_audience = env.get("JWT_AUDIENCE", "").strip() or None

    def verify(self, token: str) -> Dict[str, Any]:
        """Return ``{"sub", "role", "tenant", "issuer", "auth_mode"}`` or raise TokenRejected."""
        if self.mode == AUTH_MODE_OIDC:
            return self._verify_oidc(token)
        return self._verify_shared_secret(token)

    def _verify_shared_secret(self, token: str) -> Dict[str, Any]:
        required = ["exp", "sub"]
        if self._jwt_issuer:
            required.append("iss")
        if self._jwt_audience:
            required.append("aud")
        try:
            claims = jwt.decode(
                token,
                self._shared_secret(),
                algorithms=["HS256"],
                issuer=self._jwt_issuer,
                audience=self._jwt_audience,
                options={"require": required, "verify_aud": self._jwt_audience is not None},
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenRejected("Token has expired") from exc
        except jwt.InvalidTokenError as exc:
            logger.warning("Authorization rejected: %s", type(exc).__name__)
            raise TokenRejected("Invalid token") from exc

        role = claims.get("role")
        if role not in KNOWN_ROLES:
            logger.warning("JWT rejected: missing or unrecognized role %r", role)
            raise TokenRejected("Invalid token")
        return {
            "sub": claims["sub"],
            "role": role,
            "tenant": None,
            "issuer": claims.get("iss"),
            "auth_mode": SHARED_SECRET_MODE,
        }

    def _get_jwks_client(self) -> Any:
        if self._jwks_client is None and self._oidc is not None:
            self._jwks_client = jwt.PyJWKClient(self._oidc.jwks_url, cache_keys=True, lifespan=_JWKS_CACHE_SECONDS)
        return self._jwks_client

    def _verify_oidc(self, token: str) -> Dict[str, Any]:
        settings = self._oidc
        if settings is None:
            raise TokenRejected("Invalid token")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            raise TokenRejected("Invalid token") from exc
        if header.get("alg") not in settings.algorithms:
            logger.warning("OIDC token rejected: disallowed algorithm %r", header.get("alg"))
            raise TokenRejected("Invalid token")

        try:
            signing_key = self._get_jwks_client().get_signing_key_from_jwt(token)
        except jwt.PyJWKClientConnectionError as exc:
            logger.error("OIDC JWKS endpoint unavailable: %s", exc)
            raise TokenRejected("Identity provider unavailable", status=503) from exc
        except jwt.PyJWKClientError as exc:
            logger.warning("OIDC authorization rejected: unknown signer (%s)", exc)
            raise TokenRejected("Invalid token") from exc

        try:
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=list(settings.algorithms),
                issuer=settings.issuer,
                audience=settings.audience,
                leeway=settings.leeway,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenRejected("Token has expired") from exc
        except jwt.InvalidTokenError as exc:
            logger.warning("OIDC authorization rejected: %s", type(exc).__name__)
            raise TokenRejected("Invalid token") from exc

        tenant = str(claims.get("tid") or "").lower() or None
        if settings.allowed_tenants and tenant not in settings.allowed_tenants:
            logger.warning("OIDC token rejected: tenant %r is not allowed", tenant)
            raise TokenRejected("Invalid token")

        raw_roles = claims.get(settings.role_claim) or []
        if isinstance(raw_roles, str):
            raw_roles = [raw_roles]
        role = _highest_role(settings.role_map.get(str(value), "") for value in raw_roles)
        if role is None:
            logger.warning("OIDC principal %r has no OpenShield role assigned", claims.get("sub"))
            raise TokenRejected("This identity is not assigned an OpenShield role", status=403)

        return {
            "sub": claims["sub"],
            "role": role,
            "tenant": tenant,
            "issuer": claims["iss"],
            "auth_mode": AUTH_MODE_OIDC,
        }


def build_verifier(shared_secret: Callable[[], str], env: Mapping[str, str] = os.environ) -> TokenVerifier:
    """Create the verifier for the configured mode, failing closed on bad config."""
    mode = load_auth_mode(env)
    oidc = load_oidc_settings(env) if mode == AUTH_MODE_OIDC else None
    return TokenVerifier(mode, shared_secret, oidc=oidc, env=env)
