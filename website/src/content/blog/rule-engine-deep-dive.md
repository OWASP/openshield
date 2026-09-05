---
title: "Under the Hood: Engineering a Dynamic Rule Orchestration Engine"
description: "A technical deep-dive into how OpenShield uses Python dynamic imports and SDK abstraction to scale security coverage."
pubDate: 2026-05-28
author: "OpenShield Engineering"
tags: ["engineering"]
draft: false
---

When we designed the OpenShield scanner, we knew that hardcoding security rules into the core engine was a recipe for technical debt. We needed a system where a security researcher could drop a new `.py` file into a folder and have it immediately active.

## One file, one rule

Adding coverage never touches the engine. A rule is a small contract: metadata constants plus one `scan()` function. Here is the shape of AZ-STOR-001, the rule that flags public blob access (abridged; the shipped rule emits the full finding record):

```python
RULE_ID = "AZ-STOR-001"
RULE_NAME = "Public Blob Access Enabled on Storage Account"
SEVERITY = "HIGH"
CATEGORY = "Storage"
FRAMEWORKS = {"CIS": "3.5", "NIST": "PR.AC-3", "ISO27001": "A.9.4.1"}

def scan(azure_client, subscription_id):
    return [
        finding
        for account in azure_client.get_storage_accounts()
        if getattr(account, "allow_blob_public_access", False)
    ]
```

The engine walks `scanner/rules/`, dynamically imports every `az_*.py` file and calls `scan()`. Nothing anywhere in the core lists the rules by name, so a pull request that adds a rule is exactly one new file.

## The AzureClient Abstraction

Rules shouldn't deal with the complexities of Azure's many SDKs. We built the `AzureClient` wrapper in `scanner/azure_client.py` to provide typed accessors and unified auth. A rule author calls `get_storage_accounts()` and never instantiates an SDK client, never reads an environment variable and never handles a token refresh.

The abstraction pays for itself again in tests: the validation suite points the scanner at cached inventory instead of a live tenant, so every rule is exercised in CI without any Azure subscription.

![How a rule file becomes a finding: dynamic import, metadata contract, AzureClient accessors, finding record, playbook reference](/openshield/diagrams/rule-engine.svg)

*Fig. 1: the engine never hardcodes a rule. AzureClient sits under the contract and the finding.*

## Severity and compliance are data

`SEVERITY` follows the shared severity contract documented in `docs/severity-contract.md`, so HIGH means the same thing in every rule and in every report. `FRAMEWORKS` maps the rule to real control identifiers, which is how a single finding can answer four auditors at once. Neither is inferred by heuristics; both are declared by the rule author and reviewed like code, because they are code.

## From finding to fix

A finding that ends at "you have a problem" is only half a product. Rules may declare a `PLAYBOOK` path, and `playbooks/cli/` ships a `fix_az_*.sh` script per remediation: idempotent, printed with the exact `az` command, and safe to dry-run. The report links the two, so the path from finding to fixed state is one hop.

## Adding your own rule

1. Create `scanner/rules/az_<domain>_<nnn>.py` following `docs/adding-a-rule.md`.
2. Run the scanner against test inventory and confirm your rule fires and stays quiet on clean inventory.
3. Open a pull request with a DCO sign-off; CI compiles every rule and runs the validation suite.

That is the entire contribution surface. One file in, one pull request, and every OpenShield deployment in the world gets your coverage on the next merge.
