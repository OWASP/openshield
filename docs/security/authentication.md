# Authentication, token containment and secret rotation

This page covers how the OpenShield API authenticates callers, how to set up an
enterprise identity provider, and what to do if a bearer credential or
`JWT_SECRET` may have been exposed. It tracks issue #294.

## What changed and why

The dashboard used to copy a pre-signed JWT from the `VITE_JWT_TOKEN` build
variable into `localStorage`, falling back to a `dev-local-token` placeholder.
Anything in a `VITE_*` variable is compiled into the public JavaScript bundle,
so that token was readable by anyone who loaded the site, and `localStorage`
kept it available to any script on the page.

Current behavior:

- The frontend never reads a build-time token and never persists one. Tokens
  are held in memory for the life of the page (`api.setToken`), and a legacy
  `jwt_token` entry in `localStorage` is deleted on load without being used.
- CI builds the dashboard with a canary `VITE_JWT_TOKEN` and fails if any
  JWT-shaped value, the canary, or `dev-local-token` appears in `frontend/dist`.
- The API supports an `oidc` mode that trusts only an enterprise identity
  provider's signing keys and app-role assignments.

## Choosing a mode

| | `shared_secret` (default) | `oidc` |
|---|---|---|
| Who can mint a token | Anyone holding `JWT_SECRET` | Only the identity provider |
| Role source | `role` claim chosen by whoever signs | App roles assigned in the IdP |
| Tenant check | None | `tid` must be in `OIDC_ALLOWED_TENANTS` (when set) |
| Revocation | Rotate `JWT_SECRET` (invalidates every token) | Remove the role assignment or disable the user; tokens expire on the IdP's lifetime |
| Use for | Local development, CI smoke tests | Any deployment holding real scan data |

The API logs a startup warning when `shared_secret` mode runs in production.

## Configuring Microsoft Entra ID

1. **Register the API.** In Entra ID, create an app registration for the
   OpenShield API. Under **Expose an API**, set the Application ID URI (for
   example `api://openshield`).
2. **Define app roles** on that registration, allowed for users/groups (and
   applications, if automation needs them):

   | Value | Grants |
   |---|---|
   | `OpenShield.Viewer` | Read-only API access |
   | `OpenShield.Operator` | Read plus scan trigger and AI endpoints |
   | `OpenShield.Admin` | Everything an operator can do |

3. **Require assignment.** In the enterprise application, enable
   **Assignment required** and assign users or groups to the roles. Identities
   without a role receive `403`.
4. **Set the tokens to v2** (`accessTokenAcceptedVersion: 2` in the manifest)
   so the issuer below matches.
5. **Configure the API:**

   ```bash
   OPENSHIELD_AUTH_MODE=oidc
   OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
   OIDC_AUDIENCE=<application-client-id>   # the aud claim in issued access tokens
   OIDC_JWKS_URL=https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys
   OIDC_ALLOWED_TENANTS=<tenant-id>
   ```

   Optional: `OIDC_ROLE_CLAIM` (default `roles`), `OIDC_ROLE_MAP`
   (`<claim value>=viewer|operator|admin`, comma-separated),
   `OIDC_ALGORITHMS` (asymmetric only, default `RS256`), and
   `OIDC_CLOCK_SKEW_SECONDS` (0–300, default 60).

The API refuses to start if `oidc` mode is missing the issuer, audience or JWKS
URL, if the JWKS URL is not HTTPS, or if a symmetric algorithm is configured.
Signing keys are cached for five minutes, so IdP key rotation is picked up
automatically. If the JWKS endpoint is unreachable, requests fail closed with
`503`.

A browser sign-in flow (Authorization Code with PKCE) for the dashboard is
tracked separately under #294. Until it lands, the dashboard sends no token:
reads work only against an API running with `OPENSHIELD_PUBLIC_DEMO=true` and
non-sensitive data, and writes require calling the API with an IdP-issued
token.

## Containment checklist: a bearer token or `JWT_SECRET` may be exposed

Work through these in order and record each step, with times and the person
who performed it, on a private security advisory or incident issue.

1. **Stop further exposure.** Remove the value from wherever it leaked
   (frontend build variables, CI variables, logs, tickets). For a
   `VITE_JWT_TOKEN`, delete the variable in the hosting provider and redeploy
   the frontend from a commit that includes this change.
2. **Suspend the API if data may be at risk.** Scale the API service to zero or
   block public ingress until the remaining steps are complete.
3. **Rotate `JWT_SECRET`.** Generate a new value and set it in the API
   environment:

   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

   Restarting with the new secret invalidates every token signed with the old
   one. Update any CI secret used by smoke tests at the same time.
4. **Prefer `oidc` mode** for the restored deployment so no long-lived shared
   signing secret authorizes access.
5. **Restrict scope.** Set `OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS` to the
   subscriptions this deployment may scan, and confirm
   `OPENSHIELD_PUBLIC_DEMO` is unset for any deployment with real data.
6. **Review access.** Pull API request logs for the exposure window and look
   for write requests (`POST /api/scans/trigger`, `/api/ai/*`), requests for
   unexpected subscription IDs, and unfamiliar source addresses. Each log line
   carries a request ID for correlation.
7. **Verify before restoring.** Confirm that:
   - a request with the old token returns `401`;
   - `grep -rE 'eyJ[A-Za-z0-9_-]{8,}\.eyJ' frontend/dist` finds nothing in the deployed build;
   - a `viewer` identity receives `403` on `POST /api/scans/trigger`;
   - in `oidc` mode, a token for another tenant or audience returns `401`.
8. **Restore and record.** Re-enable the API, then close the incident with the
   evidence from step 7.

## Rotating `JWT_SECRET` routinely

Rotate at least when a maintainer with access leaves, whenever a leak is
suspected, and before re-enabling a suspended deployment. Rotation has no
overlap window: tokens signed with the old secret stop working as soon as the
API restarts, so schedule it with any smoke-test or automation owners.

## Remaining work tracked in #294

- Dashboard sign-in with Authorization Code and PKCE.
- Persisted organization/tenant ownership for scans, findings, resources, drift
  and AI data, with tenant context required in every repository query, and an
  evaluation of PostgreSQL row-level security.
- Cross-tenant integration tests across scans, findings, compliance, resources,
  drift, AI and enrichment routes.
