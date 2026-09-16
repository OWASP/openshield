#!/usr/bin/env python3
"""
Generate a demo JWT for the OpenShield frontend.

The token is signed with the same JWT_SECRET used by the Render backend.
Set the result as VITE_JWT_TOKEN in the Vercel environment to allow the
frontend to authenticate against read (GET) /api/* endpoints.

Usage:
    JWT_SECRET=<your-production-secret> python scripts/generate_demo_jwt.py
    JWT_SECRET=<your-production-secret> DEMO_JWT_TTL_HOURS=8 python scripts/generate_demo_jwt.py

The API now requires every token to carry an expiry and rejects any request
whose role isn't recognized (see issue #294) - this token expires after
DEMO_JWT_TTL_HOURS (default 24) and must be regenerated after that, and its
"viewer" role means it can never authorize a write (scan trigger, AI
endpoints). It is still a bearer credential once issued: treat it like a
password - set it only in the Vercel dashboard, never commit it to the repo,
and regenerate it (this script, or a fresh JWT_SECRET) if it may have leaked.
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
        "Usage: JWT_SECRET=<your-production-secret> python scripts/generate_demo_jwt.py"
    )

_DEFAULT_TTL_HOURS = 24.0
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

print(f"\nGenerated demo JWT, expires in {ttl_hours:g}h (set this as VITE_JWT_TOKEN on Vercel):\n")
print(token)
print(
    "\nNEVER commit this token or the JWT_SECRET to the repository.\n"
    "Set it only in the Vercel dashboard → Settings → Environment Variables.\n"
    "Regenerate before it expires - there is no automatic renewal.\n"
)
