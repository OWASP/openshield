# OpenShield Render deployment

OpenShield uses a manual, deterministic GitHub Actions workflow to deploy the API
and scan worker to Render. Deployments are coordinated around one immutable GitHub
SHA, but they are not atomic.

- Blueprint: [`render.yaml`](../../render.yaml)
- Workflow: [`.github/workflows/deploy.yml`](../../.github/workflows/deploy.yml)
- Deploy client: [`scripts/render_deploy.py`](../../scripts/render_deploy.py)

## Service layout

| Environment | Service | Type | Branch | Start command |
|---|---|---|---|---|
| Staging | `openshield-api-staging` | web | `dev` | `./startup.sh` |
| Staging | `openshield-worker-staging` | worker | `dev` | `python -m scanner.worker` |
| Production | `openshield-api` | web | `main` | `./startup.sh` |
| Production | `openshield-worker` | worker | `main` | `python -m scanner.worker` |

All four services use `autoDeployTrigger: "off"`. Render does not independently
deploy either worker or API service; GitHub Actions is the sole deployment
controller. The workflow may only be dispatched as follows:

- `staging` from the `dev` branch;
- `production` from the `main` branch.

Any other branch/environment combination fails during preflight before a Render
deployment is created. The job uses the selected GitHub Environment, allowing
maintainers to add approval gates and protection rules for staging or production.

The API startup applies database migrations with `alembic upgrade head` and then
executes Gunicorn. The worker runs only in its separate Render worker service.

## Required configuration

Configure these GitHub Actions secrets for every deployment:

| Secret | Purpose |
|---|---|
| `RENDER_API_KEY` | Authenticate Render API requests |
| `RENDER_STAGING_SERVICE_ID` | Staging API service ID |
| `RENDER_STAGING_WORKER_SERVICE_ID` | Staging worker service ID |
| `RENDER_PRODUCTION_SERVICE_ID` | Production API service ID |
| `RENDER_PRODUCTION_WORKER_SERVICE_ID` | Production worker service ID |
| `STAGING_API_URL` | Staging API health and smoke-test URL |
| `PRODUCTION_API_URL` | Production API health and smoke-test URL |

When `run_smoke_tests` is enabled, these existing secrets are also mandatory:

- `JWT_SECRET`
- `AZURE_SUBSCRIPTION_ID`
- `AZURE_CLIENT_ID`
- `AZURE_CLIENT_SECRET`
- `AZURE_TENANT_ID`

They are not required for a health-only deployment. The preflight validates every
value required for the selected operation before either deployment POST and never
prints secret values.

Each Render service also needs its application environment configured. Within an
environment, the API and worker must use matching `DATABASE_URL` and `JWT_SECRET`
values and the required Azure credentials. Values declared with `sync: false` in
the Blueprint must be configured in Render and are never stored in this repository.

The two API services also require `ALLOWED_ORIGINS`. Set the staging API to its
staging frontend origin and the production API to its production frontend origin.
When more than one origin is required, use the comma-separated format accepted by
the Flask application. Leaving this value unset enables wildcard CORS and is not
acceptable for a real staging or production environment. Do not add this setting to
worker services.

## Restricting probe/scrape endpoints at the edge

`/health`, `/ready`, and `/metrics` are intentionally exempt from JWT auth (see
`api.app._ALWAYS_PUBLIC`) so uptime checkers and Prometheus scrapers can reach them
without a token. `/health` is a pure liveness check with no backend dependency and is
meant to stay reachable from anywhere - it is what `render.yaml`'s
`healthCheckPath` uses. `/ready` and `/metrics` are different: `/ready` checks out a
pooled database connection on every call, and `/metrics` returns operational counters
(including database pool utilization from `openshield_db_pool_connections_*` -
counts only, never the DSN, host, or credentials - see `get_pool_stats()` in
`api/models/finding.py`). Neither should be reachable by arbitrary internet clients.

Render's Blueprint format has no path-based access control, so this repository
cannot restrict `/ready`/`/metrics` from `render.yaml` itself. The application
carries its own in-process, in-memory rate limit on both paths
(`api.observability.probe_rate_limit`, wired in `api/app.py`) as a defense-in-depth
backstop - deliberately not the shared Postgres-backed `api.rate_limit.rate_limit`
used elsewhere, since that would add database load to the exact endpoint meant to
protect the database from overload. That backstop bounds a single source hammering
one process; it is not a substitute for restricting network reachability.

Whoever operates the reverse proxy, CDN, or WAF in front of a Render deployment
(Cloudflare or similar, if one is configured) should restrict `/ready` and `/metrics`
to known monitoring/scraping source IPs or an internal network path, the same way
they would for any other backend-only operational endpoint. This is an operational
configuration step outside this repository, not something `render.yaml` can express.

## Coordinated deterministic deployment

For the selected environment, the workflow:

1. validates the selected branch, service IDs, API URL, SHA, Render key, and any
   enabled smoke-test credentials;
2. creates one API deployment pinned to `github.sha` and records its exact ID;
3. creates one worker deployment pinned to the same `github.sha` and records its
   exact ID;
4. polls each exact deployment ID independently until both are `live`;
5. runs the API `/health` gate only after both services are live;
6. optionally runs the smoke suite only after both deployments and health succeed.

The deployment-creation POST is attempted once. An ambiguous POST network failure
may mean Render accepted the request even though Actions did not receive its ID, so
automatically repeating the POST could create a duplicate deployment.

Polling GET requests retry transient network failures, HTTP 429, and selected HTTP
5xx responses with bounded backoff. Permanent errors, malformed responses, terminal
Render failures, and the overall timeout fail immediately. Retry time counts against
the overall timeout. Logs identify the service, SHA, deployment ID when known, and
last status without printing credentials.

## Migration and worker startup ordering

API startup owns database migration execution through `alembic upgrade head`. The
worker can begin querying PostgreSQL while a migration is still completing, so it
may temporarily encounter database errors; the current worker loop catches these
errors and retries. This does not make every future migration safe. Non-backward-
compatible schema changes require deliberate API/worker rollout planning, and
maintainers should monitor worker logs during the first deployment after a schema
migration. Do not run migrations independently in both services.

## Partial failure and recovery

API and worker deployment is coordinated, not atomic. Possible partial states
include:

- the API deployment is created but worker creation fails;
- one deployment reaches `live` while the other fails;
- Actions loses contact while Render continues an accepted deployment;
- a rerun creates new deployment IDs for the same SHA.

When this happens:

1. inspect both services in Render and record the API and worker deployment IDs;
2. confirm the commit SHA attached to each deployment;
3. rerun the workflow from the correct branch for a current-branch deployment, or
   use the manual rollback procedure below for a historical SHA;
4. do not manually deploy a different commit to only one service;
5. confirm both services converge on the same SHA before treating the environment
   as healthy.

If the initial POST failed ambiguously, first inspect Render for a deployment at the
requested SHA before rerunning. A rerun is safe operationally only when maintainers
understand whether the earlier request was accepted.

## Worker verification limitation

Render reporting the worker deployment as `live` proves that Render deployed and
started the service. It does not prove that the worker can connect to the database,
claim queued scans, process them, or persist completed results. This repository does
not currently expose a worker heartbeat or queue-processing health endpoint.
Application-level worker verification therefore remains a separate live step: queue
a controlled scan and confirm it is claimed and completed successfully.

## Blueprint validation

Local YAML parsing verifies syntax only. It is not equivalent to validation against
Render's current Blueprint schema. Maintainers may validate the Blueprint through
the Render dashboard preview or Render's supported Blueprint validation API before
syncing services. Live validation requires Render credentials and must not be
reported as completed unless the live API or dashboard was actually used.

## Manual deployment and verification

1. Open **Actions > Deploy API and worker to Render > Run workflow**.
2. Select `dev` with `staging`, or `main` with `production`.
3. Choose whether to run the real-scan smoke tests.
4. Record the GitHub SHA and both Render deployment IDs from the workflow logs.
5. Confirm the API health result and, if enabled, the smoke-test result.
6. Perform the application-level worker verification described above.
7. Confirm both Render services report the same SHA.

A normal workflow dispatch always deploys `github.sha` from the selected current
`dev` or `main` ref. It cannot deploy an arbitrary historical SHA.

## Rollback

Historical rollback must currently be performed with the deployment client or the
Render dashboard/API. The rollback is coordinated but not atomic: invoke it for
both API and worker using the same known-good SHA, capture both deployment IDs, and
confirm both services converge before treating the environment as healthy.

Create and wait for the API deployment:

```bash
RENDER_API_KEY="<render-api-key>" \
RENDER_SERVICE_ID="<api-service-id>" \
RENDER_SERVICE_NAME="API" \
GITHUB_SHA="<known-good-sha>" \
python scripts/render_deploy.py create
# deploy_id=<deployment-id>

RENDER_API_KEY="<render-api-key>" \
RENDER_SERVICE_ID="<api-service-id>" \
RENDER_SERVICE_NAME="API" \
RENDER_DEPLOY_ID="<deployment-id>" \
GITHUB_SHA="<known-good-sha>" \
python scripts/render_deploy.py wait
```

Repeat the equivalent commands for the worker:

```bash
RENDER_API_KEY="<render-api-key>" \
RENDER_SERVICE_ID="<worker-service-id>" \
RENDER_SERVICE_NAME="worker" \
GITHUB_SHA="<known-good-sha>" \
python scripts/render_deploy.py create
# deploy_id=<deployment-id>

RENDER_API_KEY="<render-api-key>" \
RENDER_SERVICE_ID="<worker-service-id>" \
RENDER_SERVICE_NAME="worker" \
RENDER_DEPLOY_ID="<deployment-id>" \
GITHUB_SHA="<known-good-sha>" \
python scripts/render_deploy.py wait
```

For a simpler one-service operation, default `deploy` mode creates and waits for a
single service:

```bash
RENDER_API_KEY="<render-api-key>" \
RENDER_SERVICE_ID="<service-id>" \
RENDER_SERVICE_NAME="<API-or-worker>" \
GITHUB_SHA="<known-good-sha>" \
python scripts/render_deploy.py deploy
```

Run that command separately for both matching services and confirm both report the
same SHA. These examples are documented procedures only; no live rollback was run
as part of this change.
