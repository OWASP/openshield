# Adding a New Scan Rule

This is the fastest way to contribute to OpenShield. You can write, test, and submit a new rule in under 30 minutes.

---

## The Rule Template

Create a new file in `scanner/rules/`. The filename should match your rule ID in lowercase with underscores:

```
scanner/rules/az_stor_001.py  ← for rule AZ-STOR-001
```

Every rule file must have this exact structure:

```python
"""AZ-XXXX-000: One-line description of what this rule detects."""

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# ── Required module-level constants ─────────────────────────────────────────

RULE_ID = "AZ-XXXX-000"  # Unique ID. Check existing rules to avoid clashes.
RULE_NAME = "Human-readable name"  # Shown in the dashboard and reports.
SEVERITY = "HIGH"  # CRITICAL | HIGH | MEDIUM | LOW | INFO
CATEGORY = "Storage"  # Storage | Network | Identity | Database | Compute | Key Vault | Kubernetes
FRAMEWORKS = {
    "CIS": "3.5",  # CIS Azure Benchmark control ID
    "NIST": "PR.AC-3",  # NIST CSF subcategory
    "ISO27001": "A.9.4.1",  # ISO 27001 Annex A control
}
DESCRIPTION = (
    "Explain WHY this is a security risk. One or two sentences. "
    "What can an attacker do if this misconfiguration exists?"
)
REMEDIATION = "Explain HOW to fix it. What setting to change, or what command to run."
PLAYBOOK = "playbooks/cli/fix_az_xxxx_000.sh"  # path to the matching fix script


# ── Required scan function ───────────────────────────────────────────────────


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Return a list of findings. Return [] if no issues are found.

    Args:
        azure_client:    An AzureClient instance with all SDK clients pre-configured.
        subscription_id: The Azure subscription ID being scanned.

    Returns:
        A list of finding dicts. Each dict must contain the keys below.
    """
    findings: List[Dict[str, Any]] = []

    for resource in azure_client.get_storage_accounts():  # ← replace with the right method
        resource_id = getattr(resource, "id", "")
        resource_name = getattr(resource, "name", "")
        if not resource_id or not resource_name:
            continue

        allows_public_access = bool(getattr(resource, "allow_blob_public_access", False))
        status = False if allows_public_access else True

        if status is None:
            # Could not determine compliance because of permissions,
            # SDK failure, or another unexpected state. Skip rather than
            # create a false positive.
            logger.warning("%s: could not determine status for %s", RULE_ID, resource_name)
            continue

        if status is False:
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": resource_id,
                    "resource_name": resource_name,
                    "resource_type": "Microsoft.Storage/storageAccounts",  # ← update
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {},
                }
            )

    return findings
```

---

## Field-by-Field Explanation

| Field | What to write |
|---|---|
| `RULE_ID` | `AZ-[CATEGORY]-[NUMBER]`. Prefix map: STOR, NET, IDN, DB, CMP, KV. Look at existing rules for the next number. |
| `SEVERITY` | Use the canonical [finding severity contract](severity-contract.md): `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` |
| `CATEGORY` | Matches the resource type being scanned |
| `FRAMEWORKS` | Use real CIS, NIST, and ISO 27001 control IDs. SOC 2 is mapped in `compliance/frameworks/soc2.json`. |
| `DESCRIPTION` | Focus on WHY it matters — what is the real-world attack scenario? |
| `REMEDIATION` | Be specific. Name the Azure Portal setting or the exact CLI flag. |
| `PLAYBOOK` | Path to the matching bash script in `playbooks/cli/`. You must create this file too. |
| `resource_type` | The full Azure resource provider type string, e.g. `Microsoft.Network/networkSecurityGroups` |

---

## AzureClient Methods Available

| Method | Returns |
|---|---|
| `azure_client.get_storage_accounts()` | List of StorageAccount objects |
| `azure_client.get_storage_lifecycle_policy(rg, name)` | `True` if a lifecycle policy with rules exists, `False` if no policy exists, `None` if it cannot be checked |
| `azure_client.get_network_security_groups()` | List of NetworkSecurityGroup objects |
| `azure_client.get_network_interface(rg, name)` | NetworkInterface or None |
| `azure_client.get_virtual_networks()` | List of VirtualNetwork objects |
| `azure_client.get_public_ip_addresses()` | List of PublicIPAddress objects |
| `azure_client.get_virtual_machines()` | List of VirtualMachine objects |
| `azure_client.get_postgresql_servers()` | List of Server objects (PostgreSQL single-server) |
| `azure_client.get_sql_servers()` | List of Server objects (Azure SQL) |
| `azure_client.get_sql_server_auditing_policy(rg, name)` | ServerBlobAuditingPolicy or None |
| `azure_client.get_key_vaults()` | List of Vault objects (with full properties) |
| `azure_client.get_managed_clusters()` | List of AKS ManagedCluster objects, or `None` on API failure |
| `azure_client.get_applications()` | Paginated App Registration dictionaries, or `None` on Graph failure |
| `azure_client.get_managed_identity_service_principals()` | Managed Identity service principals, or `None` on Graph failure |
| `azure_client.get_subscription_role_assignments()` | Subscription RBAC assignments, or `None` on API failure |
| `azure_client.get_service_principals()` | List of RoleAssignment objects for service principals |
| `azure_client.get_conditional_access_policies()` | List of CA policy dicts from MS Graph |
| `azure_client.get_function_app_security_posture()` | Cached, secret-free Function App posture dicts, or `None` on API failure |
| `azure_client.get_private_endpoint_posture()` | Public-access and approved Private Link state for supported PaaS resources, or `None` on API failure |
| `azure_client.get_recovery_vault_security_posture()` | Cached Recovery Services vault security settings, or `None` on API failure |
| `azure_client.get_container_registries()` | List of ACR Registry objects, or `None` on API failure |
| `azure_client.get_blob_containers(rg, account)` | List of blob container items (with `public_access`), or `None` on API failure |
| `azure_client.get_blob_service_properties(rg, account)` | BlobServiceProperties (versioning, soft delete), or `None` on API failure |
| `azure_client.devops_client` | `DevOpsClient` instance, or `None` if `AZURE_DEVOPS_ORG_URL`/`AZURE_DEVOPS_PROJECT` are not configured |
| `azure_client.devops_client.get_service_endpoints()` | List of Azure DevOps service connections, or `None` on API failure |
| `azure_client.parse_resource_id(id)` | Dict with `resource_group` and `name` |

List methods return an empty list on failure. Single-resource methods return `None` when the resource cannot be fetched. Three-state checks, such as `get_storage_lifecycle_policy()`, return `True` for compliant, `False` for non-compliant, and `None` when the scanner cannot determine the state.

When a helper returns `None`, skip the resource and log a warning. Never create a finding from an unknown state.

`azure_client.devops_client` is `None` whenever Azure DevOps is not configured for the scanned subscription — treat that the same as "not applicable" and return no findings, not as an indeterminate failure.

---

## Optional: Reporting Evaluation Coverage (`evaluate()`)

`scan()` only ever reports violations, so a scan with no findings for your rule is indistinguishable from "everything is compliant," "nothing of this resource type exists," and "the rule errored before it could check anything." A rule can additionally expose:

```python
from scanner.evaluation import EvaluationStatus, RuleEvaluation, subscription_scope_id


def evaluate(azure_client: Any, subscription_id: str) -> List[RuleEvaluation]:
    """Report a status for every resource this rule looked at, PASS included."""
```

to state a `PASS`/`FAIL`/`UNKNOWN`/`ERROR`/`NOT_APPLICABLE` result per resource instead of only per violation. This is additive: `scan()` keeps working unchanged, and a rule without `evaluate()` still runs, its coverage is just recorded as `UNKNOWN`/`LEGACY_RULE_NOT_MIGRATED` rather than assumed to be a pass.

Rules of the contract (see `scanner/evaluation.py` and `scanner/rules/az_kv_006.py` for the reference implementation):

- `resource_id` must be a real, non-empty identifier. For a subscription-level result with no single resource to blame, use `subscription_scope_id(subscription_id)`, never `""`.
- `UNKNOWN`, `ERROR`, and `NOT_APPLICABLE` require a `reason_code` explaining why — never leave one unexplained.
- A `FAIL` result may attach `finding=` with the same dict shape `scan()` returns; the engine deduplicates it against anything `scan()` already reported for the same `(rule_id, resource_id)`, so implementing both never double-counts.
- If you can't tell "no resources of this type exist" apart from "the list call failed" (a real gap in some `AzureClient` methods today), report `NOT_APPLICABLE` rather than guessing `PASS`.

You don't need to migrate an existing rule's `scan()` to add `evaluate()` — most rules can leave `scan()` exactly as-is.

---

## Write the Remediation Playbook

Create a matching bash script in `playbooks/cli/`:

```bash
#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-XXXX-000 — Your Rule Name
# Usage: ./fix_az_xxxx_000.sh <resource-group> <resource-name>
# Severity: HIGH

set -e

RESOURCE_GROUP=$1
RESOURCE_NAME=$2

if [ -z "$RESOURCE_GROUP" ] || [ -z "$RESOURCE_NAME" ]; then
  echo "Usage: $0 <resource-group> <resource-name>"
  exit 1
fi

# The actual az CLI command to fix the issue
az <service> <resource-type> update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$RESOURCE_NAME" \
  --<setting> <value>

echo "Remediation complete for $RESOURCE_NAME"
```

---

## Test Your Rule Locally

```bash
# 1. Set credentials
# Create a .env file and fill in your Azure credentials

# 2. Load env and run your rule in isolation
python -c "
from dotenv import load_dotenv; load_dotenv()
import os
from scanner.azure_client import AzureClient
from scanner.rules import az_xxxx_000 as rule  # replace with your module name

client = AzureClient(os.environ['AZURE_SUBSCRIPTION_ID'])
findings = rule.scan(client, os.environ['AZURE_SUBSCRIPTION_ID'])
print(f'Found {len(findings)} issue(s):')
for f in findings:
    print(f'  [{f[\"severity\"]}] {f[\"resource_name\"]} — {f[\"rule_name\"]}')
"

# 3. Or run the full scan engine (loads all rules)
python -c "
from dotenv import load_dotenv; load_dotenv()
import json, os
from scanner.engine import ScanEngine
engine = ScanEngine(os.environ['AZURE_SUBSCRIPTION_ID'])
result = engine.run_scan()
print(json.dumps(result, indent=2))
"
```

---

## Update the Compliance Framework Files

If your rule maps to controls not yet in the compliance JSON files, add entries to the relevant file(s) in `compliance/frameworks/`:

- `cis_azure_benchmark.json`
- `nist_csf.json`
- `iso27001.json`
- `soc2.json`

```json
{
  "controls": {
    "AZ-XXXX-000": {
      "control_id": "3.7",
      "control_name": "CIS control name here",
      "description": "Why this control is relevant to your finding."
    }
  }
}
```

---

## Submit a Pull Request

```bash
git checkout -b rule/az-xxxx-000-short-description
git add scanner/rules/az_xxxx_000.py playbooks/cli/fix_az_xxxx_000.sh
git commit -m "feat: add rule AZ-XXXX-000 — short description"
git push origin rule/az-xxxx-000-short-description
```

Then open a PR. Use the PR template — it will ask you for the rule ID, severity, and which frameworks you mapped. A maintainer will review within 48 hours.

Before requesting review, make sure all seven CI checks pass:

- Python syntax on rule files
- Rule structure validation
- Hardcoded credential scan
- Playbook existence and bash syntax
- Compliance JSON validation
- API syntax check
- Compliance rule cross-reference

---

## Common Mistakes to Avoid

- **Rule ID clash**: always check `scanner/rules/` for existing IDs before numbering your rule.
- **Missing playbook**: every rule must have a matching `playbooks/cli/fix_*.sh` file.
- **Hardcoded subscription ID**: use the `subscription_id` parameter passed to `scan()`, never hardcode.
- **Exceptions crashing the scan**: the engine catches unhandled exceptions per rule, but write defensively — use `getattr(obj, "field", default)` for optional SDK attributes.
- **Empty `frameworks` dict**: always populate the CIS, NIST, and ISO27001 keys even if you map to `"N/A"`, and add the SOC 2 mapping in `soc2.json`.



## Real-world impact of selected rules

**AZ-STOR-001 — Public blob access enabled**
This is how 38 million records leaked in the 2021 Power Apps breach — blob containers set to public, no authentication needed, just know the URL and download everything. Attackers don't even need to "hack" anything. Automated tools scan Azure for public blobs constantly. If yours is exposed it will be found, usually within hours.

**AZ-STOR-002 — Storage account allows unencrypted HTTP**
Any data moving over plain HTTP can be read by anyone on the same network path. This sounds theoretical until you realise most corporate VPNs, shared offices and cloud interconnects are exactly that kind of shared environment. One internal tool uploading customer data over HTTP to Azure storage is all it takes. The fix is one toggle — HTTPS only — but it gets missed constantly.

**AZ-STOR-003 — Storage account has no lifecycle management policy**
Without lifecycle management, old blobs pile up forever. Backups, exports and stale customer files stay accessible long after the business reason for keeping them has expired. Lifecycle policies give teams a way to tier or delete data automatically instead of relying on someone to remember a cleanup task months later.

**AZ-NET-001 — NSG allows SSH from internet**

SSH brute force attacks are constant — attackers run automated scripts trying millions of username and password combinations against any open port 22 they find. In 2023 a university research cluster was compromised through an exposed SSH port, with attackers using it to mine cryptocurrency for three months before detection. Restricting SSH to known IP ranges or using Azure Bastion eliminates this risk entirely.


**AZ-NET-002 — NSG allows RDP from internet**

RDP on port 3389 open to 0.0.0.0/0 is one of the most scanned ports on the internet — automated bots find it within minutes of a VM being provisioned. The 2021 Colonial Pipeline attack started with an exposed RDP port and a compromised password. Once an attacker gets in via RDP they have full GUI access to the machine and can move laterally across the entire network.


**AZ-IDN-001 — Overprivileged service principal**
Contributor at subscription scope means the service principal can touch everything — every VM, every database, every storage account across the whole subscription. The moment that client secret leaks — through a git commit, a build log, a misconfigured app — the attacker has the keys to the kingdom. This exact pattern showed up in the SolarWinds breach. Least privilege is not optional.

**AZ-IDN-002 — MFA not enforced on privileged accounts**
Credential stuffing is not sophisticated. Attackers just take leaked password lists from other breaches and try them on Azure AD. Without MFA a matching password is all they need. Microsoft says MFA stops 99.9% of these attacks. A Global Admin account without MFA is genuinely one of the highest risk findings you can have — one leaked password from any other service and your entire tenant is gone.

**AZ-DB-001 — PostgreSQL server allows public network access**
Public database endpoints get scanned constantly. Even if credentials are strong, a reachable database server gives attackers a place to brute force, exploit, or pressure-test configuration mistakes. PostgreSQL should sit behind private networking unless there is a deliberate, reviewed reason to expose it.

**AZ-DB-002 — Azure SQL Server auditing disabled**
When auditing is off, failed logins, schema changes and suspicious database access leave little evidence behind. The incident response team starts with a blank timeline. Enabling auditing gives you the raw event trail needed for investigations and compliance reporting.

**AZ-CMP-001 — VM with public IP and no associated NSG**
A virtual machine with a public IP and no NSG on its network interface has no explicit network filtering at the NIC boundary. If the workload was meant to be private, this creates a direct path from the internet to the VM. Attach an NSG, restrict inbound rules, or remove the public IP entirely.

**AZ-KV-001 — Key Vault soft delete disabled**
Key Vault is where everything important lives — database passwords, API keys, TLS certificates, encryption keys. Without soft delete an attacker or a disgruntled employee can delete every single secret permanently in about 30 seconds. No recovery, no rollback. A real incident in 2021 saw an employee delete an entire production Key Vault on their last day. The company was down for 6 days rebuilding access from scratch. Soft delete costs nothing to enable.

**AZ-KV-002 — Key Vault allows public network access**
Key Vault should be one of the least reachable services in an Azure environment. Public network access does not mean secrets are public, but it does widen the path attackers can use to attempt access. Private endpoints and network restrictions keep secret access inside trusted network boundaries.

For the complete current rule list, see `docs/rules-reference.md`.
