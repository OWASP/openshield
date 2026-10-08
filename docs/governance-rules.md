# Enterprise Governance Rules

`AZ-GOV-001` through `AZ-GOV-010` evaluate Azure management hierarchy, policy assignments and exemptions, RBAC, resource locks, provider registration, ownership metadata, and unresolved policy drift.

## Configuration

Copy `config/governance-policy.example.json` to an organisation-controlled location, replace every example value, and set:

```bash
export OPENSHIELD_GOVERNANCE_POLICY=/secure/path/governance-policy.json
```

The scanner does not invent governance defaults. If the policy is missing or invalid, the rules log an `UNKNOWN` result and do not create a finding. Evidence collections are independently nullable, so a permission failure in one Azure API does not become a false pass or false failure in another control.

## Evidence and permissions

The collector uses read-only Azure Resource Manager and Resource Graph requests. Grant only the read permissions listed in each finding. Policy state collection also needs `Microsoft.PolicyInsights/policyStates/queryResults/action`.

Resource scope is determined by the configured production resource types and production tag. Valid exclusions are exact, case-insensitive resource ID matches. Policy and RBAC assignment IDs are compared at their effective Azure scopes.

## Remediation safety

Every governance playbook requires the literal `--apply` flag. Review inherited access, policy impact, active exceptions, and workload dependencies before running it. The exemption playbook intentionally stops with operator guidance because exemption metadata schemas are organisation-specific.

## Current scanner contract

The scanner persists findings and per-resource rule evaluations. Governance rules currently emit findings through the legacy scan interface, so the engine records UNKNOWN coverage with LEGACY_RULE_NOT_MIGRATED rather than inferring PASS from an empty finding list. Dedicated governance coverage evaluators are still required before these controls can contribute affirmative compliance or resolve lifecycle findings.
