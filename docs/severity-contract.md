# Finding Severity Contract

OpenShield uses [`contracts/severity.v1.json`](../contracts/severity.v1.json) as the single semantic source for finding severity. Scanner rules, persistence, API validation, scoring, resource risk, prioritization, Sentinel export, frontend filters, charts, and Tailwind colors consume this contract through the Python or JavaScript adapter. The frontend commits a byte-equivalent generated mirror under `frontend/src/generated/` because its Vercel project root is `frontend/`; `npm run test:severity` rejects any drift.

## Version 1.0.0

| Severity | Rank | Posture deduction per finding | Matrix risk | Meaning |
|---|---:|---:|---:|---|
| `CRITICAL` | 4 | 20 | 10 | Immediate exploitation or catastrophic business-impact risk |
| `HIGH` | 3 | 10 | 8 | Direct, material security risk |
| `MEDIUM` | 2 | 5 | 5 | Indirect or partial security risk |
| `LOW` | 1 | 2 | 2 | Security hardening or best-practice gap |
| `INFO` | 0 | 0 | 1 | Informational evidence that does not reduce the posture score |

`INFORMATIONAL` is accepted only as an input alias and is persisted and returned as `INFO`. Unknown values are rejected. `NONE` is a resource-view sentinel, not a finding severity. Evaluation states such as `PASS`, `UNKNOWN`, or `NOT_APPLICABLE` are also not severities.

The v1 posture score is `max(0, 100 - sum(finding deductions))`. This model only describes severity arithmetic. Issue #263 tracks evidence completeness; a future coverage-aware score must not present incomplete collection or rule execution as a clean result.

Prioritization may raise an impact label when many affected resources compound risk, but it must never lower the label below the finding's canonical severity.

## Changing the contract

Severity meaning is a public data contract. A change to an ID, alias, rank, weight, risk score, label, tone, or color requires all of the following in one coordinated release:

1. Add a new immutable contract file (for example, `severity.v2.json`), run `npm run sync:severity` in `frontend/`, and update both adapters. Do not edit v1 semantics in place after release.
2. Add an Alembic migration that inventories existing values, explicitly maps supported legacy values, rejects unknown data, updates the database constraint, and backfills stored scores and the contract version.
3. Update scanner, API, Sentinel, frontend, documentation, and contract tests together. No consumer may maintain a fallback severity order or weight map.
4. Drain scanner workers and validate the migration against a production-sized staging copy before rollout. Document the expected score changes and rollback limitations. Contract provenance is nullable so any legacy worker result that lands during a rollout cannot be mislabeled as v1.
5. Deploy and wait for the migration-owning API before creating the worker deployment. Then verify scanner/database score parity plus every severity-facing API and dashboard view.

Downgrades cannot truthfully restore scores that were previously calculated with incorrect semantics. Treat a score repair as an auditable data correction and retain the contract version on each scan.
