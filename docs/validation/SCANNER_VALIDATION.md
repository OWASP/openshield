# Scanner Validation

This document describes how to validate the OpenShield scanner and its rule
surface. It is based on the current contents of `scanner/rules/*.py`.

All execution status is `Pending` until a contributor records manual results
in `docs/validation/TEST_RESULTS.md`.

## Scanner Entry Point

The scanner entry point is:

```python
from scanner.engine import ScanEngine

result = ScanEngine(subscription_id).run_scan()
```

`ScanEngine` is defined in `scanner/engine.py`.

## Rule Loading

`ScanEngine.load_rules()` dynamically imports Python files from:

```text
scanner/rules/*.py
```

Rule files are loaded in sorted path order. Any module with a callable
`scan()` function is added to the scan engine's rule list. Files without a
callable `scan()` function are skipped.

During `run_scan()`, each loaded rule is called as:

```python
rule.scan(azure_client, subscription_id)
```

The scanner expects each rule to return a list of finding dictionaries. If a
rule returns a non-list value, that rule's result is skipped. If a rule raises
an exception, the scan continues with the remaining rules.

## Expected Rule Format

Each rule module should define these module-level values:

```python
RULE_ID = "AZ-STOR-001"
RULE_NAME = "Public Blob Access Enabled on Storage Account"
SEVERITY = "HIGH"
CATEGORY = "Storage"
FRAMEWORKS = {"CIS": "3.5", "NIST": "PR.AC-3", "ISO27001": "A.9.4.1"}
DESCRIPTION = "..."
REMEDIATION = "..."
PLAYBOOK = "playbooks/cli/fix_az_stor_001.sh"
```

Each rule should expose:

```python
def scan(azure_client, subscription_id):
    return []
```

The expected finding fields are:

| Field | Purpose |
|---|---|
| `rule_id` | Stable OpenShield rule ID, for example `AZ-STOR-001` |
| `rule_name` | Human-readable rule title |
| `severity` | Canonical severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` |
| `category` | Rule category such as `Storage`, `Network`, or `Key Vault` |
| `resource_id` | Full Azure resource ID when available |
| `resource_name` | Azure resource name |
| `resource_type` | Azure provider type, for example `Microsoft.Storage/storageAccounts` |
| `description` | Security impact of the finding |
| `remediation` | Human-readable remediation guidance |
| `playbook` | Path to the matching remediation playbook |
| `frameworks` | Compliance mappings |
| `metadata` | Optional rule-specific context |

`ScanEngine.run_scan()` adds `scan_id` and `detected_at` when a finding does
not already include them.

## Verified Rule Matrix

The following matrix was verified from actual files in `scanner/rules`.

Total verified rule files: **64**

| Category | Count | Rule IDs |
|---|---:|---|
| Compute | 4 | `AZ-CMP-001`, `AZ-CMP-002`, `AZ-CMP-003`, `AZ-CMP-004` |
| Database | 7 | `AZ-DB-001`, `AZ-DB-002`, `AZ-DB-003`, `AZ-DB-004`, `AZ-DB-005`, `AZ-DB-006`, `AZ-DB-007` |
| Cosmos DB | 2 | `AZ-COSMOS-001`, `AZ-COSMOS-002` |
| Identity | 19 | `AZ-IDN-001`, `AZ-IDN-002`, `AZ-IDN-003`, `AZ-IDN-004`, `AZ-IDN-005`, `AZ-IDN-006`, `AZ-IDN-007`, `AZ-IDN-008`, `AZ-IDN-009`, `AZ-IDN-016`, `AZ-IDN-017`, `AZ-IDN-018`, `AZ-IDN-019`, `AZ-IDN-020`, `AZ-IDN-021`, `AZ-IDN-022`, `AZ-IDN-023`, `AZ-IDN-024`, `AZ-IDN-025` |
| Key Vault | 4 | `AZ-KV-002`, `AZ-KV-003`, `AZ-KV-004`, `AZ-KV-005` |
| KeyVault | 1 | `AZ-KV-001` |
| Network | 14 | `AZ-NET-001`, `AZ-NET-002`, `AZ-NET-003`, `AZ-NET-004`, `AZ-NET-005`, `AZ-NET-006`, `AZ-NET-007`, `AZ-NET-008`, `AZ-NET-009`, `AZ-NET-010`, `AZ-NET-011`, `AZ-NET-012`, `AZ-NET-013`, `AZ-NET-014` |
| PostQuantum | 3 | `AZ-PQC-001`, `AZ-PQC-002`, `AZ-PQC-003` |
| Storage | 9 | `AZ-STOR-001`, `AZ-STOR-002`, `AZ-STOR-003`, `AZ-STOR-004`, `AZ-STOR-005`, `AZ-STOR-006`, `AZ-STOR-007`, `AZ-STOR-008`, `AZ-STOR-009` |
| Managed Cache | 1 | `AZ-CACHE-001` |

## Initial Live Validation Candidates

These rules are the first candidates for real Azure validation because they
can be tested with low-cost resources and clear cleanup boundaries.

| Rule ID | Rule Name | Reason for Initial Selection | Status |
|---|---|---|---|
| `AZ-STOR-001` | Public Blob Access Enabled on Storage Account | Uses a low-cost storage account configuration setting | Pending |
| `AZ-NET-001` | NSG Allows Unrestricted Inbound SSH from Any Source | Uses an NSG rule only; no VM required | Pending |
| `AZ-NET-002` | NSG Allows Unrestricted Inbound RDP from Any Source | Uses an NSG rule only; no VM required | Pending |
| `AZ-KV-002` | Key Vault Allows Public Network Access Without Private Endpoint | Uses a Key Vault network setting; no secret material needed | Pending |
| `AZ-KV-004` | Key Vault Purge Protection Disabled | Uses a Key Vault protection setting; must avoid enabling purge protection during cleanup testing | Pending |

## Rules To Defer

Defer the following groups until the low-cost path is reliable:

- Identity rules that need tenant-level or Microsoft Graph permissions.
- Compute rules that require virtual machines.
- Network rules that require Application Gateway, VPN Gateway, Azure Firewall,
  load balancers, or public IP resources.
- Database rules that require SQL or PostgreSQL resources.
- PostQuantum rules that require App Service, Key Vault keys, or certificates.

## Known Scanner Notes

- `AZ-KV-001` uses category `KeyVault`, while `AZ-KV-002` through
  `AZ-KV-005` use `Key Vault`. Validation reports should preserve the current
  scanner output but note the inconsistency.
- `AZ-NET-012` references `azure_client.get_nsg_flow_logs(...)`, but that
  method is not currently present on `AzureClient`. Treat real Azure results
  for `AZ-NET-012` as `Pending investigation` until the scanner surface is
  reviewed.
- Real Azure validation must not be run automatically in PR CI.
