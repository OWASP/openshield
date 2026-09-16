# CI Pipeline

OpenShield runs GitHub Actions on every pull request to `dev` and `main`. The pipeline is split into **parallel, independent jobs** so total wall-time is the slowest single job rather than the sum of all checks. A change cannot merge until every required job passes.

This document explains each job, how to reproduce every check locally before opening a PR, the branch-protection model, and the reasoning behind the tools chosen.

---

## Jobs at a glance

`.github/workflows/ci.yml` (runs on PRs to `dev` and `main`):

| Job | Gate | What fails it |
|---|---|---|
| **Lint (ruff)** | `ruff check` + `ruff format --check` | Any lint violation or unformatted file |
| **Rule & Compliance Validation** | 7 static checks (below) | Rule/playbook/compliance-JSON problems |
| **Secret Scan (Gitleaks)** | `gitleaks detect` | A hardcoded secret in the working tree |
| **SAST (Bandit)** | `bandit -r api/ scanner/ ai/ -ll` | A medium+ severity insecure-code pattern |
| **SAST (Semgrep)** | `semgrep scan --config p/security-audit --config p/owasp-top-ten --config p/python --config p/javascript --error` | A finding from the security-audit / OWASP Top 10 / Python / JS rulesets |
| **SCA (pip-audit)** | `pip-audit -r requirements.txt` | A dependency with a known CVE (minus documented ignores) |
| **SBOM (Syft)** | CycloneDX SBOM generated + uploaded as an artifact | SBOM generation error |
| **Container Runtime + Scan (Trivy)** | Builds one image, starts that tag against PostgreSQL, requires `/ready`, verifies its runtime UID is non-root, then scans the same tag | Boot failure, database-readiness failure, root runtime, or an unfixed policy-blocking vulnerability |
| **Backend Tests (pytest + coverage)** | Full `tests/` suite against an ephemeral Postgres, `--cov-fail-under=80` | A failing test or coverage below the Silver-level floor |
| **Frontend (lint + build)** | `npm ci` → `eslint` → `vite build` | An eslint error or a broken dashboard build |
| **Enforce dev to main source** | `main` PRs must come from `dev` | A non-`dev` branch opening a PR into `main` |
| **CI Summary** | Aggregates all job results into the run summary and fails if any required job failed | Any required job failing |

`.github/workflows/codeql.yml` (separate workflow, PRs to `dev`/`main` + weekly cron): **Analyze (python)** and **Analyze (javascript)** — CodeQL semantic/taint analysis.

`.github/workflows/release.yml` (triggered by `v*` tags): requires a verified signed annotated tag, builds a deterministic source archive and CycloneDX SBOM, publishes SHA-256 checksums and identity-bound provenance attestations, then creates the GitHub Release.

The **Container Runtime + Scan** job is a required gate. Deleting the Dockerfile, breaking the WSGI target, losing database connectivity, running as root, or failing the Trivy policy makes the final CI summary fail.

---

## Setup for local runs

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install ruff bandit pip-audit semgrep  # lint / SAST / SCA tools
```

A local PostgreSQL is needed for the backend tests. Any Postgres 14+ works; create the CI-matching role/db once:

```bash
psql postgres -c "CREATE ROLE ci LOGIN PASSWORD 'ci';"
psql postgres -c "CREATE DATABASE ci_db OWNER ci;"
```

Gitleaks and Syft are single binaries (install via your package manager, e.g. `brew install gitleaks syft`, or download the release binary).

---

## Running each gate locally

Run these from the repo root. If a command exits non-zero, CI fails too.

### Lint (ruff)

```bash
ruff check .
ruff format --check .
```

Config lives in `pyproject.toml` (`line-length = 120`, rule set `E,F,W`, `target-version = py311`). To auto-fix: `ruff format .` then `ruff check --fix .`.

### Rule & Compliance Validation (7 checks)

```bash
# 1. Rule-file syntax
for f in scanner/rules/az_*.py; do python -m py_compile "$f"; done

# 2. Rule structure + RULE_ID uniqueness   (imports each rule module and checks attrs)
# 3. Hardcoded-credential grep
# 4. Playbook existence + `bash -n`
# 5. Compliance JSON validity
# 6. API/module syntax (api ai scanner sentinel)
# 7. Compliance-control -> rule-file cross-reference
```

Checks 2–7 are the same scripts embedded in the `rule-validation` job; copy them from `.github/workflows/ci.yml` to run standalone. Their rationale is preserved in **Testing-method rationale** below.

### Secret Scan (Gitleaks)

```bash
gitleaks detect --source . --no-git -v --exit-code 1
```

`--no-git` scans the working tree (fast, PR-appropriate). Note it does **not** scan full git history — a secret committed and later removed within a branch's history is not caught here; GitHub's native push-protection (enabled at the repo level) is the second layer for that.

### SAST (Bandit)

```bash
bandit -r api/ scanner/ ai/ -ll
```

`-ll` reports medium severity and above. Confirmed false positives are annotated inline with `# nosec <ID>` and a one-line justification (e.g. binding `0.0.0.0` inside a container, a parameterized SQL string).

### SAST (Semgrep)

```bash
semgrep scan \
  --config p/security-audit \
  --config p/owasp-top-ten \
  --config p/python \
  --config p/javascript \
  --exclude venv --exclude frontend/node_modules --exclude frontend/dist \
  --metrics=off \
  --error .
```

Uses the public Semgrep Registry rulesets (`p/...`) directly, not `--config auto`, since `auto` nudges toward a semgrep.dev account/login, which this project deliberately avoids. `--metrics=off` disables Semgrep's anonymous telemetry. `venv/`, `node_modules/`, and `dist/` are already excluded by Semgrep's built-in default ignores and this repo's `.gitignore`, so no `.semgrepignore` is needed; the `--exclude` flags above just make that exclusion visible in the command itself. In CI, findings are also written to SARIF and uploaded to the GitHub Security → Code scanning tab alongside CodeQL's results.

### SCA (pip-audit)

```bash
pip-audit -r requirements.txt \
  --ignore-vuln PYSEC-2025-217 --ignore-vuln CVE-2026-1839 --ignore-vuln CVE-2026-4372
```

The three ignores are advisories in `transformers` (a transitive dependency of `sentence-transformers`) with no non-breaking fix available yet; they are tracked for a coordinated ML-stack bump rather than silently dropped.

### Backend Tests (pytest + coverage)

```bash
DATABASE_URL="postgresql://ci:ci@localhost/ci_db" OPENSHIELD_ENV="testing" \
  pytest tests/ -v --tb=short --cov=api --cov=scanner --cov-report=term --cov-fail-under=80
```

Runs the **entire** `tests/` suite once (not just rule tests). Tests requiring a vector store or an AI API key skip cleanly. `--cov-fail-under=80` enforces the OpenSSF Silver statement-coverage requirement for the measured API and scanner packages.

### Frontend (lint + build)

```bash
cd frontend && npm ci && npm run lint && npm run build
```

### Container runtime + vulnerability scan

The CI job builds a single commit-tagged image, starts that exact tag as a non-root user against PostgreSQL 16, and polls the database-aware `/ready` endpoint before passing the same tag to Trivy. It always removes the smoke container, prints its logs when runtime verification fails, and still runs Trivy when a successfully built image fails to boot.

For a local end-to-end runtime check:

```bash
docker compose --profile local up --build
curl --fail http://127.0.0.1:8000/ready
docker compose --profile local down
```

Compose's `local` profile is not production configuration. Its credentials are development-only, all exposed ports bind to loopback, API startup applies Alembic migrations, and the worker waits for API readiness before polling the shared database.

---

## Branch protection and the promotion flow

The branch flow is `feature/* → dev → main`. Protection is applied to the two **destinations**; feature branches stay unprotected for fast iteration.

```
feat/* fix/* docs/* infra/*  ──PR──▶  dev   ──PR──▶  main  ──▶ production environment
      (unprotected)              (gate)        (stricter gate)
```

### Declared state (source of truth)

Protection is declared as code in GitHub's repository-ruleset format:

| Branch | File | Reviews | Required checks |
|---|---|---|---|
| `dev` | [`.github/branch-protection/dev.json`](../.github/branch-protection/dev.json) | 1 approval, code owner review, approval of the latest push, stale approvals dismissed, conversations resolved | `CI Summary`, `DCO sign-off`, `dependency-review`, `Analyze (python)`, `Analyze (javascript)` — strict (head must be up to date) |
| `main` | [`.github/branch-protection/main.json`](../.github/branch-protection/main.json) | Same as `dev`, but **2 approvals** | Same as `dev`, strict |

Both rulesets block branch deletion and force pushes and declare **no standing bypass actors**. `CI Summary` already fails when any CI job fails, including **Enforce dev to main source**, which blocks any PR into `main` whose source branch is not `dev`. `require_last_push_approval` means the person who pushed the last commit cannot provide the approval that satisfies the rule, so a promotion cannot be self-approved.

`tests/test_check_branch_protection.py` fails if a declared ruleset is weakened (fewer approvals, non-strict checks, a bypass actor) or names a required check that no workflow job produces — a misspelled required check would otherwise block every merge.

### Applying the rulesets (repository administrators)

Only an administrator can change protection. Import each file once, either through **Settings → Rules → Rulesets → New ruleset → Import a ruleset**, or with the API:

```bash
gh api -X POST repos/OWASP/openshield/rulesets --input .github/branch-protection/dev.json
gh api -X POST repos/OWASP/openshield/rulesets --input .github/branch-protection/main.json
```

To change an existing ruleset, edit the JSON file in a reviewed PR first, then apply it with `gh api -X PUT repos/OWASP/openshield/rulesets/<id> --input <file>`. Once the rulesets are active, remove the legacy classic protection so there is one source of truth. The **production** environment should keep required reviewers with **Prevent self-review** enabled.

### Effective state (evidence)

The **Branch Protection Audit** workflow (`.github/workflows/branch-protection-audit.yml`) runs weekly and on demand. It compares the rules GitHub actually enforces (`GET /repos/{repo}/rules/branches/{branch}`) with the declared files, fails on any drift, and uploads a JSON evidence record as the `branch-protection-evidence` artifact (kept 90 days). Run it locally with:

```bash
python scripts/check_branch_protection.py --validate-only
GITHUB_TOKEN=<token> python scripts/check_branch_protection.py --repo OWASP/openshield --evidence evidence.json
```

A read-only token can see enforced rules. Bypass actors are only returned to a token that can administer rulesets; store one as the `BRANCH_PROTECTION_AUDIT_TOKEN` secret, otherwise bypass actors are reported as *unverified* rather than assumed compliant.

As of the 2026-08-21 audit recorded in issue #298, both branches reported `protected: true` but required status-check enforcement was `off` and no rulesets existed. Until an administrator applies the rulesets above and the audit passes, treat the review and check requirements in this section as **declared, not enforced**.

To demonstrate enforcement after applying (acceptance criteria for #298): open a throwaway PR with a deliberately failing test and confirm merge is blocked; push to `dev` after that PR's last CI run and confirm the stale head cannot merge; open a `dev → main` PR and confirm its author cannot satisfy the approval requirement.

### Emergency changes

There is no standing bypass. If a production incident requires merging without the normal gates:

1. Open an issue labelled `priority: critical` describing the incident, the change and why the gates cannot be met.
2. An administrator temporarily switches the affected ruleset's enforcement to **Evaluate** (or adds themselves as a bypass actor), merges the reviewed fix, and restores **Active** immediately.
3. Record the time window, the actor and the merged commit on the issue, then run the Branch Protection Audit workflow and attach its evidence to the issue.
4. The change still receives a retrospective review from a second maintainer.

### Post-merge CI and automated statistics

CI and CodeQL also run on every push to `dev` and `main`, so each merged commit has its own result instead of relying only on a PR run against an older base. Post-merge runs are never cancelled.

The **Update Learn Page and README Stats** workflow no longer pushes to `dev`. When statistics change it force-updates the `docs/refresh-learn-page-stats` branch and opens (or refreshes) a pull request, which goes through the same protected flow. Pull requests opened with the default `GITHUB_TOKEN` do not start workflows, so administrators should provide a `STATS_BOT_TOKEN` secret (GitHub App token or fine-grained token with contents and pull-requests write) and allow GitHub Actions to create pull requests in repository settings.

---

## Tooling decisions

- **Gitleaks via the release binary, not `gitleaks-action`.** The Action requires a (free) `GITLEAKS_LICENSE` for **organization**-owned repos; the CLI binary is Apache-2.0 with no key, so it runs with zero license friction.
- **All third-party actions are pinned to a full commit SHA** with a `# vX.Y.Z` comment (GitHub's supply-chain hardening standard). `aquasecurity/trivy-action` is SHA-pinned specifically because its mutable tags were compromised in 2026.
- **Dependabot is notify-only** (`open-pull-requests-limit: 0` for pip / github-actions / npm): it still raises alerts but does not auto-open version-bump PRs.
- **Least-privilege token:** `ci.yml` declares `permissions: contents: read`; CodeQL and Semgrep each scope their own `security-events: write`.
- **`concurrency` cancels superseded runs** on the same PR to save runner minutes.
- **Semgrep added as a second, open-source SAST layer**, run as a pure CLI invocation (`semgrep scan --config p/...`) with `--metrics=off`, no semgrep.dev account, login, or telemetry dependency. It complements CodeQL's deeper data-flow/taint analysis with fast, pattern-based rules (OWASP Top 10, general security-audit, Python/JS-specific), uploading SARIF to the same GitHub code scanning UI. Added per maintainer direction to reduce reliance on GitHub's proprietary, soon-to-be-paid "Code Quality" product in favor of open-source tooling.
- **The `p/...` rulesets are pulled from the public Semgrep Registry at run time**, not vendored, so a registry outage fails the `SAST (Semgrep)` job. Accepted as a normal SAST-gate network dependency; a spurious red on that job is worth checking against Semgrep Registry status before assuming a real finding.

---

## Testing-method rationale

### Why `py_compile` for syntax, not a linter
`py_compile` has a binary, objective outcome (does the file parse?). Style linting is now handled separately and explicitly by **ruff**, so the syntax checks stay narrowly scoped to "will this import at all".

### Why `importlib` (not regex) for structure validation
A rule's fields may be computed, inherited, or split across lines. `spec_from_file_location` + `exec_module` + `hasattr()` is the only way to be certain an attribute exists at runtime — the same mechanism the scan engine uses to load rules, so CI mirrors production.

### Why `bash -n` for playbooks
It parses a `.sh` without executing it, catching unclosed `if`/`fi`, bad heredocs, and quoting errors at zero risk of touching an Azure resource. Existence alone is insufficient — a broken playbook crashes when an operator runs it against a real finding.

### Why the credential grep uses exclusions, not an allowlist
`password=`, `secret=`, `api_key=` appear legitimately in env-var lookups and comments, which are excluded; the scan targets literal assignment (the hardcoded-value pattern). Every exclusion is visible in one place and auditable. `venv/` is excluded so local runs don't false-positive on third-party packages.

### Why the cross-reference walks compliance JSONs
It catches the deletion case: a rule file removed but its compliance-JSON entry left behind. Walking the JSONs and looking up each referenced rule ID against existing rule files surfaces stale references with the exact file and ID.

---

## The CI summary

The `ci-summary` job uses `needs: [...]` + `if: always()` so it runs after every other job regardless of outcome, reads each job's `result`, and writes a markdown pass/fail table to `$GITHUB_STEP_SUMMARY` (rendered on the Actions run page). A final step fails the job if any required job failed, including the container runtime and Trivy result.

---

## Fixing common failures

| Failure | Fix |
|---|---|
| `ruff check` / `format` fails | `ruff format .` then `ruff check --fix .`; re-run both |
| `bandit` medium+ finding | Fix it, or if a confirmed false positive add `# nosec <ID>` with a one-line reason |
| `semgrep` finding | Fix the flagged pattern, or if a confirmed false positive add a `# nosemgrep: <rule-id>` (Python) / `// nosemgrep: <rule-id>` (JS) comment with a one-line justification on the flagged line |
| `pip-audit` reports a CVE | Bump the pin to a fixed version; only add `--ignore-vuln` with a documented reason |
| `pytest` coverage below 80% | Add tests, or investigate the regression that removed coverage |
| Frontend eslint error | Fix the reported rule (e.g. remove an unused import); warnings do not fail CI |
| Container runtime or `/ready` fails | Check the Docker entrypoint, PostgreSQL connection, migration/startup logs, and non-root user; CI prints the container logs on failure |
| Trivy reports a blocking image CVE | Update the base image or affected package and rebuild; do not bypass the required container job |
| `Enforce dev to main source` fails | Open the PR from `dev`; merge feature work into `dev` first |
| `missing field 'RULE_ID'` | Add `RULE_ID = "AZ-XXX-000"` at module level in the rule file |
| `DUPLICATE RULE_ID '...'` | Assign a unique ID to the newer rule file |
| `references '...' but no matching rule file found` | Create the rule file or remove the stale compliance-JSON entry |
