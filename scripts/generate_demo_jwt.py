#!/usr/bin/env python3
"""
Mint a short-lived shared-secret JWT for local development and API smoke tests.

The token is signed with JWT_SECRET and is only accepted when the API runs with
OPENSHIELD_AUTH_MODE=shared_secret (the default). It must never be embedded in
the dashboard: the frontend no longer reads a build-time token, and anything
placed in a Vite variable is published in the public JavaScript bundle
(issue #294). Enterprise deployments use OPENSHIELD_AUTH_MODE=oidc instead; see
docs/security/authentication.md.

Usage:
    JWT_SECRET=<secret> python scripts/generate_demo_jwt.py
    JWT_SECRET=<secret> DEMO_JWT_TTL_HOURS=0.5 python scripts/generate_demo_jwt.py

The token carries an expiry (DEMO_JWT_TTL_HOURS, default 1) and the read-only
"viewer" role, so it can never authorize a write. It is still a bearer
credential: keep it out of the repository, shell history shared with others,
and any client-side configuration.
"""

import os
import sys
import time

try:
    import jwt
except ImportError:
    sys.exit("PyJWT is required: pip install pyjwt")

secret = os.environ.get("JWT_SECRET")
if not secret:
    sys.exit(
        "Error: JWT_SECRET environment variable is not set.\n"
        "Usage: JWT_SECRET=<secret> python scripts/generate_demo_jwt.py"
    )

_DEFAULT_TTL_HOURS = 1.0
try:
    ttl_hours = float(os.environ.get("DEMO_JWT_TTL_HOURS", _DEFAULT_TTL_HOURS))
except ValueError:
    sys.exit("Error: DEMO_JWT_TTL_HOURS must be a number.")
if ttl_hours <= 0:
    sys.exit("Error: DEMO_JWT_TTL_HOURS must be greater than zero.")

issued_at = int(time.time())
token = jwt.encode(
    {
        "sub": "openshield-demo",
        "role": "viewer",
        "iat": issued_at,
        "exp": issued_at + int(ttl_hours * 3600),
    },
    secret,
    algorithm="HS256",
)

print(f"\nGenerated viewer JWT for local/API testing, expires in {ttl_hours:g}h:\n")
print(token)
print(
    "\nUse it only as an Authorization header for API calls (curl, smoke tests).\n"
    "NEVER commit it, and never put it in a VITE_* variable or any other frontend configuration.\n"
)
