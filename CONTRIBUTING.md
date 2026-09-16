# Contributing to OpenShield

Welcome! OpenShield is built by the community - students, developers, and security engineers at every level. This guide will get you contributing in under 30 minutes.

---

## What Can I Contribute?

For Python development on Linux/Python 3.11, install the runtime and test tools with
`python -m pip install --require-hashes --only-binary=:all: -r requirements-dev.txt`.
Production installs use `requirements.txt` and exclude test/lint tools. See
[dependency locking](docs/dependency-locking.md) before changing dependencies.

| Contribution Type | Difficulty | Time |
|---|---|---|
| New misconfiguration scan rule | Beginner | 20–30 min |
| Remediation playbook (CLI) | Beginner | 30 min |
| Compliance framework mapping | Intermediate | 1–2 hrs |
| New API endpoint | Intermediate | 2–4 hrs |
| Dashboard MVP work | Intermediate | 2–4 hrs |
| KQL detection rule (Sentinel) | Advanced | 3–5 hrs |
| Scanner engine feature | Advanced | 4–8 hrs |

**Start with a scan rule - it is the most impactful and beginner-friendly contribution.**

---

## Adding a Scan Rule (The Fastest Way to Contribute)

Every misconfiguration rule is a self-contained Python file in `scanner/rules/`.

### Step 1 - Pick an Issue

Browse issues labelled [`good-first-issue`](https://github.com/openshield-org/openshield/issues?q=label%3Agood-first-issue) or [`help-wanted`](https://github.com/openshield-org/openshield/issues?q=label%3Ahelp-wanted).

Comment on the issue: **"I'd like to work on this"** - we will assign it to you.

### Step 2 - Fork & Clone

```bash
# Fork the repo on GitHub, then:
git clone https://github.com/YOUR_USERNAME/openshield.git
cd openshield
git checkout -b rule/your-rule-name
```

### Step 3 - Write Your Rule

Create a new file in `scanner/rules/`. Every rule follows this exact template:

```python
"""AZ-STOR-001: Public blob access enabled on storage account."""

from typing import Any, Dict, List

RULE_ID = "AZ-STOR-001"
RULE_NAME = "Public Blob Access Enabled on Storage Account"
SEVERITY = "HIGH"  # CRITICAL / HIGH / MEDIUM / LOW / INFO
CATEGORY = "Storage"  # Storage / Network / Identity / Database / Compute / Key Vault / Kubernetes
FRAMEWORKS = {"CIS": "3.5", "NIST": "PR.AC-3", "ISO27001": "A.9.4.1"}
DESCRIPTION = (
    "Storage accounts with public blob access enabled allow anyone on the "
    "internet to read data without authentication. This can lead to data "
    "exposure incidents."
)
REMEDIATION = "Disable public blob access on the storage account."
PLAYBOOK = "playbooks/cli/fix_az_stor_001.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Return a list of findings. Return [] if no issues are found."""
    findings: List[Dict[str, Any]] = []

    for account in azure_client.get_storage_accounts():
        if getattr(account, "allow_blob_public_access", False):
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": account.id,
                    "resource_name": account.name,
                    "resource_type": "Microsoft.Storage/storageAccounts",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {},
                }
            )

    return findings
```

That's it. One file, one rule.

Choose severity using the versioned [finding severity contract](docs/severity-contract.md). Rule files must use a canonical contract value; aliases such as `INFORMATIONAL` are accepted at API boundaries but are not valid rule declarations.

### Step 4 - Add a Remediation Playbook

Create the matching fix in `playbooks/cli/`:

```bash
# playbooks/cli/fix_az_stor_001.sh

#!/bin/bash
# Disable public blob access on a storage account
# Usage: ./fix_az_stor_001.sh <resource-group> <storage-account-name>

RESOURCE_GROUP=$1
STORAGE_ACCOUNT=$2

az storage account update \
  --name $STORAGE_ACCOUNT \
  --resource-group $RESOURCE_GROUP \
  --allow-blob-public-access false

echo "Public blob access disabled for $STORAGE_ACCOUNT"
```

### Step 5 - Test Your Rule

```bash
# Set up test credentials (use a free Azure trial account)
export AZURE_SUBSCRIPTION_ID=your-test-subscription
export AZURE_CLIENT_ID=your-client-id
export AZURE_CLIENT_SECRET=your-secret
export AZURE_TENANT_ID=your-tenant-id

# Run your rule against the test subscription
python -c "
import os
from scanner.azure_client import AzureClient
from scanner.rules import az_stor_001 as rule

client = AzureClient(os.environ['AZURE_SUBSCRIPTION_ID'])
findings = rule.scan(client, os.environ['AZURE_SUBSCRIPTION_ID'])
print(f'Found {len(findings)} issue(s)')
"
```

### Step 6 - Submit Your PR

```bash
git add .
git commit -m "feat: add rule AZ-STOR-001 public blob access check"
git push origin rule/your-rule-name
```

Then open a Pull Request on GitHub. Use this PR template:

```
## What does this PR do?
Adds scan rule AZ-STOR-001 - detects storage accounts with public blob access enabled.

## Rule details
- Rule ID: AZ-STOR-001
- Severity: HIGH
- Category: Storage
- Frameworks mapped: CIS 3.5, NIST PR.AC-3, ISO 27001 A.9.4.1, SOC 2 CC6.6

## Tested against
- [ ] Azure free trial subscription
- [ ] Rule returns correct findings
- [ ] Remediation playbook tested

## Related issue
Closes #123
```

---

## Rule ID Convention

Use the format: `AZ-[CATEGORY]-[NUMBER]`

| Category | Prefix | Example |
|---|---|---|
| Storage | STOR | AZ-STOR-001 |
| Network | NET | AZ-NET-001 |
| Identity | IDN | AZ-IDN-001 |
| Database | DB | AZ-DB-001 |
| Compute | CMP | AZ-CMP-001 |
| Key Vault | KV | AZ-KV-001 |
| Kubernetes (AKS) | AKS | AZ-AKS-001 |

Check existing rules before picking a number to avoid clashes.

---

## AzureClient Methods

Use the existing wrapper methods in `scanner/azure_client.py` rather than constructing Azure SDK clients directly inside a rule.

| Method | Returns |
|---|---|
| `azure_client.parse_resource_id(resource_id)` | Dict with `resource_group` and `name` |
| `azure_client.get_storage_accounts()` | List of StorageAccount objects |
| `azure_client.get_storage_lifecycle_policy(resource_group, account_name)` | `True` if a lifecycle policy with rules exists, `False` if no policy exists, `None` if the policy cannot be checked |
| `azure_client.get_network_security_groups()` | List of NetworkSecurityGroup objects |
| `azure_client.get_network_interface(resource_group, nic_name)` | NetworkInterface or None |
| `azure_client.get_virtual_networks()` | List of VirtualNetwork objects |
| `azure_client.get_public_ip_addresses()` | List of PublicIPAddress objects |
| `azure_client.get_virtual_machines()` | List of VirtualMachine objects |
| `azure_client.get_postgresql_servers()` | List of PostgreSQL single-server objects |
| `azure_client.get_sql_servers()` | List of Azure SQL Server objects |
| `azure_client.get_sql_server_auditing_policy(resource_group, server_name)` | ServerBlobAuditingPolicy or None |
| `azure_client.get_key_vaults()` | List of Key Vault objects |
| `azure_client.get_managed_clusters()` | List of AKS ManagedCluster objects, or `None` on API failure |
| `azure_client.get_applications()` | Paginated App Registration dictionaries, or `None` on Graph failure |
| `azure_client.get_managed_identity_service_principals()` | Managed Identity service principals, or `None` on Graph failure |
| `azure_client.get_subscription_role_assignments()` | Subscription RBAC assignments, or `None` on API failure |
| `azure_client.get_service_principals()` | List of role assignments for service principals |
| `azure_client.get_conditional_access_policies()` | List of Conditional Access policy dicts from Microsoft Graph |
| `azure_client.get_function_app_security_posture()` | Cached, secret-free Function App posture dicts, or `None` on API failure |
| `azure_client.get_private_endpoint_posture()` | Public-access and approved Private Link state for supported PaaS resources, or `None` on API failure |
| `azure_client.get_recovery_vault_security_posture()` | Cached Recovery Services vault security settings, or `None` on API failure |

Most list methods return an empty list on failure. Methods that fetch one resource or one policy return `None` when the result cannot be determined.

---

## Local Dev Setup

```bash
# Python 3.10+
pip install -r requirements.txt
# Installs Flask, Alembic, Azure SDK clients, requests, psycopg2, PyJWT, and PyYAML for CI workflow validation.

# Frontend
# The React dashboard lives in frontend/ and uses the repository's npm scripts.

# Database (Docker)
docker run --name openshield-db \
  -e POSTGRES_USER=openshield \
  -e POSTGRES_PASSWORD=openshield \
  -e POSTGRES_DB=openshield \
  -p 5432:5432 -d postgres

export DATABASE_URL=postgresql://openshield:openshield@localhost:5432/openshield
alembic upgrade head

# API
FLASK_APP=api/app.py flask run --debug
```

See [Database Migrations](docs/database-migrations.md) before creating or applying
a schema change. Migration revisions are written explicitly because OpenShield
does not use ORM metadata.

---

## Coding Standards

All contributions must meet these standards before a pull request will be reviewed.

**Python**

- Follow PEP 8 as enforced by Ruff.
- Run `ruff check .` and `ruff format .` before pushing.
- Use `%s` style logging instead of f-strings in logger calls.
- Add type hints to all new functions.
- Use `getattr(obj, "field", default)` for optional SDK object fields instead of direct attribute access.

**JavaScript**

- ESLint must pass with zero errors.
- Run `npm run lint` from `frontend/` before pushing frontend changes.

**Shell scripts**

- Scripts must pass `bash -n` syntax validation.
- Scripts must start with `set -euo pipefail`.
- Quote all variable expansions.

**Commit messages**

- Follow Conventional Commits using prefixes such as `feat:`, `fix:`, `docs:`, `chore:`, and `test:`.
- Reference the related issue number where applicable.

**Developer Certificate of Origin**

- By adding `Signed-off-by: Your Name <email>` to a commit, a contributor certifies the [Developer Certificate of Origin 1.1](https://developercertificate.org/).
- Use `git commit -s` to add the sign-off.
- The project lead must approve and enable DCO enforcement before this becomes a required merge check; until then, sign-off is requested but not represented as enforced.

**Branch naming**

- Use `feat/description` for new features.
- Use `fix/description` for bug fixes.
- Use `docs/description` for documentation.
- Use `infra/description` for infrastructure changes.

**Pull request requirements**

- All CI checks must pass.
- Do not commit credentials, tokens, or secrets.
- Add automated tests for major new functionality and bug fixes. If tests are not applicable, explain why in the pull request.
- New scanner rules require compliant and non-compliant test cases.
- Update all four compliance framework JSON files for new scanner rules.
- Add a CLI remediation playbook for each new scanner rule.
- Follow `.github/PULL_REQUEST_TEMPLATE.md`.
- Obtain at least one reviewer approval before merge.
- Add regression tests for bug fixes whenever the behavior can be reproduced automatically. Major functionality must include automated tests.

## OpenSSF Best Practices

OpenShield is working toward the OpenSSF Best Practices Gold badge. The repository currently enforces or provides:

- Automated testing on pull requests through GitHub Actions.
- Static analysis through CodeQL, Bandit, and Ruff.
- Dependency vulnerability checks through pip-audit, GitHub Dependency Review, Dependabot alerts, and Trivy.
- SBOM generation for releases through Syft.
- Pull request dependency review that rejects newly introduced high-severity vulnerabilities.
- Private vulnerability reporting through the process in `.github/SECURITY.md`.

Gold status must not be claimed until the project has completed the official OpenSSF assessment and satisfied every mandatory criterion.

---

## Recognition

Every contributor is listed in the README.

If you contribute 3+ rules or a major feature, you get:
- Named in the project README
- A shoutout on our LinkedIn and Discord
- A reference letter available on request for job/visa applications

---

## Need Help?

- **Discord:** Join `#openshield-dev` - ask anything, no question is too basic
- **GitHub Discussions:** For longer technical questions
- **Issues:** Tag `@core-team` if you're stuck on a PR

We respond within 24 hours. Welcome to the team.
