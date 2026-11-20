# Failure-to-status scenario matrix

Incomplete evidence must never read as compliance. This page lists every
Azure failure mode the shared tests inject (`tests/test_failure_injection.py`,
issue #389), the status each one must produce, and what the compliance report
shows for the control. It complements the evaluate() contract in
`scanner/evaluation.py` and the per-rule contract in
`tests/test_rule_evaluation_contract.py`.

The shared tests discover every rule that exposes `evaluate()`, so a rule-family
migration inherits all of the scenarios below without adding tests of its own.

## Matrix

| Failure mode | How it reaches the rule | Evaluation status | Reason code | In `failed_rule_ids` | Findings | Control status |
|---|---|---|---|---|---|---|
| Collection failed | `list_*()` returns `None` | ERROR | `INVENTORY_UNAVAILABLE` | yes | none | ERROR |
| Permission denied | `evaluate()` raises | ERROR | `EVALUATOR_EXCEPTION` | yes | none | ERROR |
| Timeout | `evaluate()` raises | ERROR | `EVALUATOR_EXCEPTION` | yes | none | ERROR |
| Throttling, retries exhausted | `evaluate()` raises | ERROR | `EVALUATOR_EXCEPTION` | yes | none | ERROR |
| Malformed `evaluate()` output | non-`RuleEvaluation` items returned | ERROR (added) | `MALFORMED_EVALUATION` | yes | none | ERROR |
| Successful empty inventory | `list_*()` returns `[]` | NOT_APPLICABLE | `NO_RESOURCES_FOUND` | no | none | NOT_APPLICABLE |
| Missing properties on one resource | resource lacks a required field | UNKNOWN for that resource | `MISSING_PROPERTIES` | no | none for it | UNKNOWN |
| Partial inventory | some resources evaluable, some not | per resource | per resource | no | FAIL resources keep their finding | worst status wins |

Two rules the table encodes:

- **Empty is not failed.** A list call that succeeds with no resources is
  NOT_APPLICABLE and does not mark the rule failed. A list call that fails is
  ERROR and does. The two must never be conflated.
- **Worst status wins.** A control's status rolls up as
  FAIL > ERROR > UNKNOWN > PASS > NOT_APPLICABLE, so a compliant resource can
  never outvote a failing or unreadable one. A rule the engine recorded in
  `failed_rule_ids` is forced to ERROR even when stale rows say PASS or UNKNOWN.

## Scope not covered yet

These acceptance criteria of #389 depend on the lifecycle engine (#311) or on a
test PostgreSQL and are tracked for a follow-up:

- Failed or partial evidence cannot resolve a lifecycle or verify a remediation.
- A later PASS verifies only the correct rule and resource (stale,
  cross-subscription, wrong-resource and duplicate-processing cases).
- Persistence round-trip of evaluations through PostgreSQL.

The cross-subscription check in the shared tests only asserts that evaluation
resource IDs stay inside the scanned subscription.

## Adding a scenario

Add a row to `SCENARIOS` in `tests/test_failure_injection.py` for a failure
that applies to every rule, or write a rule-specific test next to the shared
ones when the scenario needs a real resource shape (see the AZ-KV-006
partial-inventory tests). Update the table above in the same change.
