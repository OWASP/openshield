"""Flask application factory for the OpenShield REST API."""

import logging
import os
import sys

import jwt
from dotenv import load_dotenv
from flask import Flask, g, jsonify, request
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

from api.models.finding import DatabaseManager, get_pool_stats
from api.observability import (
    configure_logging,
    get_request_id,
    init_app,
    init_sentry,
    probe_rate_limit,
    set_pool_stats_provider,
)

load_dotenv()

configure_logging()
init_sentry()
logger = logging.getLogger(__name__)

# Paths that are always public regardless of environment or demo mode.
# /ready and /metrics are probe/scrape endpoints and must never require auth.
_ALWAYS_PUBLIC = {"/", "/health", "/ready", "/metrics"}

# Maximum accepted request body size (bytes). Guards AI endpoints and the rest
# of the API against oversized payloads tying up worker threads.
_MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 MB

_INSECURE_JWT_DEFAULT = "change-me-in-production"
_MIN_JWT_SECRET_LENGTH = 32
_MAX_AUTHORIZATION_HEADER_LENGTH = 8192
_GENERATE_CMD = 'python -c "import secrets; print(secrets.token_urlsafe(32))"'

# A token's signature proves who signed it, not what the bearer is allowed to
# do. Every accepted token must carry one of these roles (see issue #294):
# a missing/unrecognized role is treated the same as an invalid signature.
# Only operator/admin may perform a write (any non-GET/HEAD); viewer is
# read-only. This is enforced regardless of demo mode - public_demo only
# ever widens *read* access to skip the token requirement entirely, it does
# not touch write authorization.
_KNOWN_ROLES = {"viewer", "operator", "admin"}
_WRITE_ROLES = {"operator", "admin"}

# Generous enough for legitimate manual or automated readiness checks from
# one source, but bounded well under the default pool size
# (DB_POOL_MAX_CONN=10) so a single caller can never claim more than half
# the pool's capacity by itself, even if every allowed request in the
# window lands at once. See probe_rate_limit's docstring for why this is
# in-memory rather than the shared Postgres-backed rate_limit().
_READY_MAX_REQUESTS_PER_WINDOW = 5


def _is_production() -> bool:
    return (
        os.environ.get("OPENSHIELD_ENV", "").lower() == "production" or os.environ.get("RENDER", "").lower() == "true"
    )


def _is_development() -> bool:
    return (
        os.environ.get("OPENSHIELD_ENV", "").lower() == "development"
        or os.environ.get("FLASK_DEBUG", "").lower() == "true"
    )


def _resolve_jwt_secret() -> str:
    """Return the JWT signing secret, enforcing production safety rules.

    Production (OPENSHIELD_ENV=production or RENDER=true): raises RuntimeError
    if the secret is missing, is the known insecure default, or is shorter than
    32 characters.  All other environments allow the default with a loud warning.
    """
    jwt_key = os.environ.get("JWT_SECRET", "")
    if _is_production():
        if not jwt_key:
            raise RuntimeError(
                "FATAL: JWT_SECRET is not set. "
                "Production deployments require a strong, unique JWT_SECRET. "
                f"Generate one with: {_GENERATE_CMD}"
            )
        if jwt_key == _INSECURE_JWT_DEFAULT:
            raise RuntimeError(
                "FATAL: JWT_SECRET is set to the insecure default value. "
                "Production deployments must use a unique secret. "
                f"Generate one with: {_GENERATE_CMD}"
            )
        if len(jwt_key) < _MIN_JWT_SECRET_LENGTH:
            raise RuntimeError(
                f"FATAL: JWT_SECRET must be at least {_MIN_JWT_SECRET_LENGTH} characters. "
                f"Generate one with: {_GENERATE_CMD}"
            )
        return jwt_key

    if not jwt_key:
        logger.warning(
            "!!! SECURITY WARNING: JWT_SECRET NOT SET. "
            "Using insecure default for local development only. "
            "Set OPENSHIELD_ENV=production (or RENDER=true) to enforce a strong "
            "secret and block startup when it is missing. !!!"
        )
        return _INSECURE_JWT_DEFAULT

    return jwt_key


def create_app() -> Flask:
    """Create and configure the Flask application.

    Returns a fully wired Flask app with:
    - CORS enabled for all origins
    - JWT authentication middleware on all non-public routes
    - Blueprints for findings, scans, score, and compliance
    - JSON error handlers for 400, 401, 403, 404, and 500
    - Global database connection teardown
    """
    app = Flask(__name__)

    # Trust exactly one reverse-proxy hop (Render's edge) for the client IP
    # and scheme, so request.remote_addr reflects the real caller instead of
    # collapsing every client onto Render's proxy address. Rate limiting and
    # any other per-IP logic (api.observability.probe_rate_limit,
    # api.rate_limit.rate_limit) depend on this being accurate.
    #
    # This is a trust boundary, not just a convenience setting: x_for=1 makes
    # Flask take the *last* entry of an inbound X-Forwarded-For header as the
    # real client IP, on the assumption that Render's edge is the only thing
    # capable of appending to it before the request reaches this process. If
    # the origin were ever reachable directly - bypassing Render's edge, e.g.
    # a misconfigured DNS record or a leaked origin IP - a direct caller's own
    # X-Forwarded-For header would be trusted as-is, and they could set it to
    # a fresh IP on every request. Every per-IP control in this file (the
    # probe-endpoint limiter, the Postgres-backed rate limiter) would then
    # bucket each request as a "new" caller, which is equivalent to no rate
    # limiting for that path at all. Keeping the origin unreachable except
    # through Render's edge is what this setting's correctness depends on.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    # ------------------------------------------------------------------ #
    # Observability                                                        #
    # ------------------------------------------------------------------ #
    # Registered first so request IDs and request timing are available to
    # every later before_request handler (including JWT auth) and to the
    # error handlers. Also mounts the public /metrics endpoint.
    init_app(app)
    set_pool_stats_provider(get_pool_stats)

    # ------------------------------------------------------------------ #
    # Configuration & Security                                             #
    # ------------------------------------------------------------------ #
    app.config["JWT_SECRET"] = _resolve_jwt_secret()
    app.config["MAX_CONTENT_LENGTH"] = _MAX_CONTENT_LENGTH

    # ------------------------------------------------------------------ #
    # CORS                                                                  #
    # ------------------------------------------------------------------ #
    allowed_origins_raw = os.environ.get("ALLOWED_ORIGINS", "*")
    if allowed_origins_raw == "*":
        logger.warning(
            "!!! SECURITY WARNING: ALLOWED_ORIGINS NOT SET. DEFAULTING TO '*' !!! "
            "For production deployments, set this to your specific frontend domain(s)."
        )
    allowed_origins = allowed_origins_raw.split(",")
    CORS(app, resources={r"/*": {"origins": allowed_origins}})

    # ------------------------------------------------------------------ #
    # Demo mode                                                             #
    # ------------------------------------------------------------------ #
    public_demo = os.environ.get("OPENSHIELD_PUBLIC_DEMO", "false").lower() == "true"
    if public_demo:
        logger.warning(
            "PUBLIC DEMO MODE ENABLED (OPENSHIELD_PUBLIC_DEMO=true): "
            "Unauthenticated GET requests to /api/* are permitted. "
            "Do not use this setting with real Azure scan data in production."
        )

    if not os.environ.get("OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS"):
        logger.warning(
            "!!! SECURITY WARNING: OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS NOT SET !!! "
            "Any authenticated operator/admin token can trigger a scan against any "
            "subscription_id. Set this to a comma-separated allowlist of the "
            "subscription(s) this deployment is authorized to scan."
        )

    @app.teardown_appcontext
    def close_db(error=None):
        """Return the request's pooled database connection after the request."""
        for key in ("db", "db_conn"):
            db = g.pop(key, None)
            if db is None:
                continue
            try:
                db.close()
            except Exception as exc:
                logger.error("Error closing database connection: %s", exc)

    # ------------------------------------------------------------------ #
    # JWT middleware                                                         #
    # ------------------------------------------------------------------ #

    @app.before_request
    def verify_jwt() -> None:
        """Validate the Bearer token on every non-public, non-OPTIONS request."""
        if request.method == "OPTIONS":
            return None
        if request.path in _ALWAYS_PUBLIC:
            return None
        if public_demo and request.method == "GET":
            return None

        auth = request.headers.get("Authorization", "")
        if len(auth) > _MAX_AUTHORIZATION_HEADER_LENGTH or not auth.startswith("Bearer "):
            return jsonify(
                {
                    "error": "Missing or malformed Authorization header",
                    "request_id": get_request_id(),
                }
            ), 401

        token = auth.split(" ", 1)[1]
        try:
            payload = jwt.decode(
                token,
                app.config["JWT_SECRET"],
                algorithms=["HS256"],
                # A token with no expiry can never be invalidated short of a
                # full JWT_SECRET rotation - require every accepted token to
                # carry one (issue #294). MissingRequiredClaimError is a
                # subclass of InvalidTokenError, so it's already handled by
                # the except clause below.
                options={"require": ["exp"]},
            )
            g.user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired", "request_id": get_request_id()}), 401
        except jwt.InvalidTokenError:
            logger.warning("Invalid JWT token")
            return jsonify({"error": "Invalid token", "request_id": get_request_id()}), 401

        role = payload.get("role")
        if role not in _KNOWN_ROLES:
            logger.warning("JWT rejected: missing or unrecognized role %r", role)
            return jsonify({"error": "Invalid token", "request_id": get_request_id()}), 401
        if request.method not in ("GET", "HEAD") and role not in _WRITE_ROLES:
            return jsonify(
                {
                    "error": "This token's role is not authorized for write operations",
                    "request_id": get_request_id(),
                }
            ), 403

        return None

    # ------------------------------------------------------------------ #
    # Blueprints                                                            #
    # ------------------------------------------------------------------ #
    from api.routes.ai import ai_bp
    from api.routes.assurance import assurance_bp
    from api.routes.cbom import cbom_bp
    from api.routes.compliance import compliance_bp
    from api.routes.drift import drift_bp
    from api.routes.findings import findings_bp
    from api.routes.prioritization import prioritization_bp
    from api.routes.resources import resources_bp
    from api.routes.scans import scans_bp
    from api.routes.score import score_bp

    app.register_blueprint(ai_bp)
    app.register_blueprint(assurance_bp)
    app.register_blueprint(cbom_bp)
    app.register_blueprint(compliance_bp)
    app.register_blueprint(drift_bp)
    app.register_blueprint(findings_bp)
    app.register_blueprint(prioritization_bp)
    app.register_blueprint(resources_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(score_bp)

    # ------------------------------------------------------------------ #
    # Routes (public)                                                      #
    # ------------------------------------------------------------------ #

    @app.get("/")
    def index():
        return jsonify(
            {"message": "Welcome to the OpenShield REST API", "version": "1.0.0", "docs": "/docs", "status": "online"}
        )

    @app.get("/health")
    def health():
        """Liveness probe: process is up. Deliberately does not touch the DB."""
        return jsonify({"status": "ok"})

    @app.get("/ready")
    @probe_rate_limit(_READY_MAX_REQUESTS_PER_WINDOW)
    def ready():
        """Readiness probe: 200 when the database is reachable, else 503."""
        try:
            # Register the manager on Flask's request context before pinging.
            # The existing teardown handler then returns the pooled connection
            # on both the success and error paths.
            g.db = DatabaseManager()
            g.db.ping()
            return jsonify({"status": "ready"}), 200
        except Exception as exc:
            logger.warning("Readiness check failed: %s", exc)
            return jsonify({"status": "not_ready", "error": "database_unreachable"}), 503

    # ------------------------------------------------------------------ #
    # Error handlers                                                        #
    # ------------------------------------------------------------------ #

    @app.errorhandler(400)
    def bad_request(exc):
        logger.warning("Bad request: %s", exc)
        return jsonify({"error": "Bad request", "request_id": get_request_id()}), 400

    @app.errorhandler(401)
    def unauthorized(exc):
        return jsonify({"error": "Unauthorized", "request_id": get_request_id()}), 401

    @app.errorhandler(403)
    def forbidden(exc):
        return jsonify({"error": "Forbidden", "request_id": get_request_id()}), 403

    @app.errorhandler(404)
    def not_found(exc):
        return jsonify({"error": "Not found", "request_id": get_request_id()}), 404

    @app.errorhandler(413)
    def payload_too_large(exc):
        return jsonify({"error": "Request body too large"}), 413

    @app.errorhandler(500)
    def internal_error(exc):
        logger.error("Unhandled exception: %s", exc)
        return jsonify({"error": "Internal server error", "request_id": get_request_id()}), 500

    logger.info("OpenShield API created - %d blueprints registered", len(app.blueprints))
    return app


# Global application object for WSGI servers (e.g. Gunicorn, Render)
# We wrap this in a check to avoid running migrations/connecting during test collection
if (
    os.environ.get("OPENSHIELD_ENV") != "testing"
    and os.environ.get("PYTEST_CURRENT_TEST") is None
    and "pytest" not in sys.modules
):
    application = create_app()
else:
    # During testing, we provide a placeholder or let conftest handle it
    application = None

if __name__ == "__main__":
    if not application:
        application = create_app()
    application.run(
        host="0.0.0.0",  # nosec B104 - must bind all interfaces to be reachable inside a container/PaaS
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
    )
