# OpenShield Architecture

## Overview

OpenShield is a modular, open source Cloud Security Posture Management (CSPM) platform for Azure. It scans your Azure subscription against 80 security rules, maps findings to compliance frameworks (CIS, NIST CSF, ISO 27001, SOC 2), stores results in PostgreSQL, and exposes posture data through a Flask REST API consumed by a live React dashboard.

---

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│           React Dashboard  (frontend/ — deployed on Vercel)      │
│                                                                  │
│  7 pages: Monitor · Discover · Prioritize · Scan                │
│           Comply · Drift · AI                                    │
└────────────────────────────┬─────────────────────────────────────┘
                             │ HTTPS  (all GETs public, POSTs need JWT)
┌────────────────────────────▼─────────────────────────────────────┐
│                    Flask REST API  (api/)                         │
│                                                                  │
│  GET  /health                                                    │
│  GET  /api/findings          GET  /api/score                     │
│  GET  /api/findings/<id>     GET  /api/score/cve-summary         │
│  GET  /api/findings/<id>/playbook                                │
│  GET  /api/scans             POST /api/scans/trigger             │
│  GET  /api/resources         GET  /api/prioritization            │
│  GET  /api/drift             GET  /api/compliance/<framework>    │
│  POST /api/ai/ask            POST /api/ai/summary                │
│  POST /api/ai/insights       POST /api/ai/prioritise             │
└───────────┬──────────────────────────────────┬───────────────────┘
            │                                  │
┌───────────▼──────────────┐   ┌───────────────▼───────────────────┐
│     Scanner Engine        │   │     Compliance Frameworks          │
│     (scanner/)            │   │     (compliance/frameworks/)       │
│                           │   │                                    │
│  ScanEngine               │   │  cis_azure_benchmark.json          │
│    └── load_rules()       │   │  nist_csf.json                     │
│    └── run_scan()         │   │  iso27001.json                     │
│                           │   │  soc2.json                         │
└───────────┬───────────────┘   └────────────────────────────────────┘
            │
┌───────────▼──────────────────────────────────────────────────────┐
│                   Rule Modules (scanner/rules/)                   │
│                                                                   │
│  80 rule files across Storage, Network, Identity, Database,       │
│  Compute, Key Vault, AKS, post-quantum cryptography, Backup,      │
│  Serverless, Private Endpoint posture, and Supply Chain           │
└───────────┬───────────────────────────────────────────────────────┘
            │ calls
┌───────────▼──────────────────────────────────────────────────────┐
│                AzureClient (scanner/azure_client.py)             │
│                                                                   │
│  DefaultAzureCredential                                          │
│  StorageManagementClient   NetworkManagementClient               │
│  ComputeManagementClient   PostgreSQLManagementClient            │
│  SqlManagementClient       KeyVaultManagementClient              │
│  AuthorizationManagementClient   MS Graph REST API               │
└───────────┬───────────────────────────────────────────────────────┘
            │ Azure SDK calls
┌───────────▼──────────────────────────────────────────────────────┐
│                  Azure Subscription (target)                     │
└──────────────────────────────────────────────────────────────────┘
            │ findings returned to ScanEngine / API
┌───────────▼──────────────────────────────────────────────────────┐
│                 PostgreSQL Database                               │
│                 (findings, scans tables)                         │
└──────────────────────────────────────────────────────────────────┘
Scan result JSON can also be passed to Sentinel ingestion:
┌──────────────────────────────────────────────────────────────────┐
│             Sentinel ingestion (sentinel/ingest.py)               │
│      input findings JSON → HMAC-sign request → Log Analytics      │
└────────────────────────────┬─────────────────────────────────────┘
                             │ Data Collector API
┌────────────────────────────▼─────────────────────────────────────┐
│                 Microsoft Sentinel / Log Analytics                │
│            OpenShieldFindings_CL + KQL analytics rules            │
└──────────────────────────────────────────────────────────────────┘
```

---

## How the Scanner Works

### 1. Initialisation

```python
engine = ScanEngine(subscription_id="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
```

`ScanEngine.__init__` creates an `AzureClient` using `DefaultAzureCredential`, which automatically resolves credentials from (in order): environment variables, managed identity, Azure CLI, or VS Code login.

### 2. Rule Loading

```python
engine.load_rules()
```

`load_rules()` iterates over every `*.py` file in `scanner/rules/` that does not start with `_`. It uses Python's `importlib.util` to load each file as a module and checks that the module exposes a `scan()` function. This means:

- **Adding a rule requires no code change to the engine** — drop a file into `scanner/rules/` and it is automatically discovered on next startup.
- Rules that fail to load (syntax errors, missing imports) are logged and skipped. The remaining rules still run.

### 3. Scan Execution

```python
result = engine.run_scan()
```

`run_scan()` iterates through all loaded rule modules, calling `module.scan(azure_client, subscription_id)` for each. Individual rule failures are caught and logged without stopping the scan. The engine collects all findings and returns a structured result dict.

### 4. Current Rule Modules

There are 80 rule files in `scanner/rules/`. See `docs/rules-reference.md` for the full table.

| Category | Count | Rules |
|---|---|---|
| Storage | 9 | AZ-STOR-001 to 009 |
| Network | 15 | AZ-NET-001 to 015 |
| Identity | 25 | AZ-IDN-001 to 025 |
| Database | 7 | AZ-DB-001 to 007 |
| Cosmos DB | 2 | AZ-COSMOS-001 to 002 |
| Managed Cache | 1 | AZ-CACHE-001 |
| Compute | 4 | AZ-CMP-001 to 004 |
| Key Vault | 5 | AZ-KV-001 to 005 |
| Kubernetes | 6 | AZ-AKS-001 to 006 |
| Post-quantum | 3 | AZ-PQC-001 to 003 |
| Backup | 4 | AZ-BAK-001, 002, 004, 006 |
| Serverless | 5 | AZ-FUNC-001 to 005 |
| Private Endpoint | 6 | AZ-PE-001 to 006 |
| Supply Chain | 8 | AZ-SC-001 to 008 |

Every rule has a matching Azure CLI playbook in `playbooks/cli/`.

### 5. Finding Schema

Every finding returned by a rule must conform to this schema:

```python
{
    "rule_id": str,  # e.g. "AZ-STOR-001"
    "rule_name": str,
    "severity": str,  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    "category": str,  # Storage | Network | Identity | Database | Compute | Key Vault
    "resource_id": str,  # full Azure resource ID
    "resource_name": str,
    "resource_type": str,  # e.g. "Microsoft.Storage/storageAccounts"
    "description": str,
    "remediation": str,
    "playbook": str,  # path to the CLI remediation script
    "frameworks": dict,  # {"CIS": "3.5", "NIST": "PR.AC-3", "ISO27001": "A.9.4.1"}
    "metadata": dict,  # optional rule-specific context
    "detected_at": str,  # ISO 8601, added by engine
    "scan_id": str,  # UUID, added by engine
}
```

### 6. AzureClient Surface

Rules should use `scanner/azure_client.py` instead of instantiating SDK clients directly.

| Method | Purpose |
|---|---|
| `parse_resource_id(resource_id)` | Parse `resource_group` and `name` from an Azure resource ID |
| `get_storage_accounts()` | List storage accounts |
| `get_storage_lifecycle_policy(resource_group, account_name)` | Return `True`, `False`, or `None` for storage lifecycle policy status |
| `get_network_security_groups()` | List network security groups |
| `get_network_interface(resource_group, nic_name)` | Fetch one network interface |
| `get_virtual_networks()` | List virtual networks |
| `get_public_ip_addresses()` | List public IP addresses |
| `get_virtual_machines()` | List virtual machines |
| `get_postgresql_servers()` | List PostgreSQL single-server instances |
| `get_sql_servers()` | List Azure SQL servers |
| `get_sql_server_auditing_policy(resource_group, server_name)` | Fetch SQL Server blob auditing policy |
| `get_key_vaults()` | List Key Vaults |
| `get_service_principals()` | List service principal role assignments |
| `get_conditional_access_policies()` | Fetch Conditional Access policies from Microsoft Graph |

---

## How Findings Flow to the API

```
run_scan()
    → findings[] in memory
    → CVE enrichment via NVD API (cve_references, cvss_score, exploit_available)
    → db.save_scan(result)           # persists to PostgreSQL
    →   scans row: scan_id, subscription_id, started_at, completed_at,
                   total_findings, score (severity-weighted 0-100),
                   severity_contract_version
    →   findings rows: one per finding with full metadata + CVE fields
    → return scan result JSON

All dashboard data endpoints are scoped to the most recent scan that has findings
(WHERE total_findings > 0 ORDER BY started_at DESC LIMIT 1), so seeded or last
good scan data is always visible even if a later scan produces zero results.

GET /api/findings
    → db.get_findings(filters)       # reads from PostgreSQL, latest scan only
    → returns { count, findings[] }

GET /api/score
    → db.get_score()                 # contract v1: CRITICAL -20, HIGH -10, MEDIUM -5, LOW -2
    → returns { status, score, max_score } — status is "OK" (score: 0-100) or
      "NO_SCAN_DATA" (score: null) when no completed scan exists yet, never a
      false 100

GET /api/resources
    → aggregates unique resources from latest scan's findings
    → returns { summary, resources[] }

GET /api/prioritization
    → ranks findings by severity_weight × affected_resource_count
    → returns { matrix[], rankings[], action_items[], summary }

GET /api/drift
    → compares two most recent scans with findings
    → returns { summary, events[] } with ADDED / REMOVED events

GET /api/findings/<id>/playbook
    → loads playbooks/cli/fix_<rule>.sh + CVE references
    → returns { portal_steps[], cli_commands[], validation_steps[], references[] }

GET /api/compliance/<framework>
    → joins DB findings with compliance/frameworks/<framework>.json
    → supported: cis, nist, iso27001, soc2
    → returns per-control pass/fail breakdown + score_percent
```

---

## How Rules Are Loaded Dynamically

The engine uses Python's `importlib` to load rule files at runtime. No registry or central list is needed:

```python
for rule_path in sorted(RULES_DIR.glob("*.py")):
    if rule_path.name.startswith("_"):
        continue
    spec = importlib.util.spec_from_file_location(rule_path.stem, rule_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if callable(getattr(module, "scan", None)):
        self.rules.append(module)
```

Each rule module is a plain Python file — no base class, no registration decorator. The only contract is the `scan(azure_client, subscription_id)` function signature.

---

## How Sentinel Integration Works

Sentinel ingestion is implemented in `sentinel/ingest.py`. It is a standalone script, not an API route and not a DB polling worker.

The flow:
1. Load a findings JSON file from the first CLI argument, defaulting to `scanner/output/test_findings.json`.
2. Use the second CLI argument as `scan_id`, or generate one from the current UTC timestamp.
3. Accept either a raw findings list or an object with a `findings` array.
4. Normalise each finding into Sentinel-friendly fields such as `RuleId`, `RuleName`, `Severity`, `SeverityScore`, `ResourceId`, and `TimeGenerated`.
5. Validate the complete batch before sending it. If configuration or any record is invalid, reject the entire batch with a concise error and send no records.
6. HMAC-sign the payload with `SENTINEL_SHARED_KEY`.
7. POST the records to the Log Analytics Data Collector API.
8. Query and analytics rules in `sentinel/rules/` operate on `OpenShieldFindings_CL`.

Required environment variables:

| Variable | Description |
|---|---|
| `SENTINEL_WORKSPACE_ID` | Log Analytics workspace customer ID |
| `SENTINEL_SHARED_KEY` | Primary or secondary shared key for the workspace |
| `SENTINEL_LOG_TYPE` | Custom log type. Defaults to `OpenShieldFindings` |

---

## CI Pipeline

`.github/workflows/ci.yml` runs on pull requests to `dev` and `main`. It installs Python 3.11 dependencies and runs seven checks:

| # | Check | Purpose |
|---|---|---|
| 1 | Python syntax on rule files | Compiles every `scanner/rules/az_*.py` file |
| 2 | Rule structure validation | Verifies required fields, valid severity values, non-empty `FRAMEWORKS`, and unique `RULE_ID`s |
| 3 | Hardcoded credential scan | Searches source files for literal secrets and keys |
| 4 | Playbook existence and bash syntax | Requires a matching `playbooks/cli/fix_<rule>.sh` for every rule and validates it with `bash -n` |
| 5 | Compliance JSON validation | Confirms CIS, NIST, ISO 27001, and SOC 2 JSON files exist and parse |
| 6 | API syntax check | Compiles every Python file under `api/` |
| 7 | Compliance rule cross-reference | Flags compliance JSON entries that reference missing rule files |

The final CI summary step always runs and writes a pass/fail table to the GitHub Actions summary.

---

## Configuration

All runtime configuration is provided via environment variables:

| Variable | Description |
|---|---|
| `AZURE_SUBSCRIPTION_ID` | Target subscription to scan |
| `AZURE_CLIENT_ID` | Service principal client ID |
| `AZURE_CLIENT_SECRET` | Service principal client secret |
| `AZURE_TENANT_ID` | Azure AD tenant ID |
| `DATABASE_URL` | PostgreSQL connection string |
| `JWT_SECRET` | Secret used to sign/verify API JWTs |
| `SENTINEL_WORKSPACE_ID` | Log Analytics workspace ID for Sentinel push |
| `SENTINEL_SHARED_KEY` | Log Analytics workspace shared key for Sentinel ingestion |
| `SENTINEL_LOG_TYPE` | Custom log name, defaults to `OpenShieldFindings` |
