# Remediation Gate

Running a `playbooks/cli` script against a real subscription has real blast
radius. A bad proposal or a retry can change customer infrastructure. The
remediation gate (`api/models/remediation.py`, issue #266) is the code every
execution-adjacent path must go through before any agent-driven remediation
exists.

**Phase one is proposal-only.** The gate records proposals, enforces who may
advance them, and decides whether a remediation worked. It never runs a
playbook, and nothing in this repository calls `begin_execution`. No execution
path may be merged that bypasses it.

## Lifecycle

```
PROPOSED -> APPROVED -> EXECUTING -> PENDING_VERIFICATION -> VERIFIED
    |           |           |                  |
    |           |           v                  v
    |           |     EXECUTION_FAILED   VERIFICATION_FAILED
    v           v
 REJECTED    REJECTED
```

`EXECUTION_FAILED` and `VERIFICATION_FAILED` can also be moved to `REJECTED` by
a human. Every transition is one conditional `UPDATE ... WHERE status = ANY(...)`
plus an audit row in the same transaction.

## Guarantees

| Requirement | How it is enforced |
| --- | --- |
| Mandatory human approval | `begin_execution` only matches `APPROVED` rows; `approve` records who approved and when. |
| Typed allowlist, starts empty | `EXECUTION_ALLOWLIST` in code. Adding a playbook is a reviewed change, not configuration. A refused attempt is audited. |
| A retry never executes twice | `APPROVED -> EXECUTING` can be won by exactly one caller; every other call raises `InvalidTransition` and gets no grant. |
| Race-free approval | Two concurrent approvals of one `PROPOSED` row cannot both succeed. |
| One live action per finding | Partial unique index `uq_remediation_actions_one_open_per_finding`. Only `VERIFIED` and `REJECTED` release a finding. |
| Full audit log | `remediation_audit_log` records proposal, approval, execution and verification. Triggers reject `UPDATE`, `DELETE` and `TRUNCATE`. |
| Approval covers exactly what runs | `propose` stores the playbook's SHA-256 and the target (`resource_id`, `subscription_id`). The `approved` audit row records all of it. `begin_execution` recomputes the hash and refuses, with an audited `playbook_changed` refusal, if the script changed or disappeared. |
| Done means rescanned | `complete_execution(succeeded=True)` moves to `PENDING_VERIFICATION`, never `VERIFIED`. See below. |

## What the audit trail does and does not prove

Triggers stop the application, and anyone using normal SQL, from editing,
deleting or truncating audit rows. They do not stop the table owner or a
superuser, who can drop the trigger. If the trail must also be evidence against
a database operator, it needs a hash chain whose head is published outside the
database, and the application's database role should not hold
`UPDATE`/`DELETE`/`TRUNCATE` on the table. Both depend on how OpenShield is
deployed and are left out of phase one.

Playbook paths come from the database, so they are never trusted as paths:
`propose` only accepts a regular file that resolves under `playbooks/`.

## Execution is at-most-once

If a runner dies after `begin_execution`, the action stays `EXECUTING` and is
never retried automatically. The outcome on customer infrastructure is unknown,
so recovery is a human decision (`reject`, then a new proposal).

## Verification

`verify(action_id, scan_id)` accepts a later scan only if it is `completed`,
covers the same subscription, and finished after the execution. It then reads
the rule evaluation (#263) for the same rule and resource:

| Rescan evaluation | Result |
| --- | --- |
| `PASS` | `VERIFIED`: the action closes and the finding is released |
| `FAIL` | `VERIFICATION_FAILED`: stays open, a new proposal is refused |
| missing, `UNKNOWN`, `ERROR`, `NOT_APPLICABLE` | `inconclusive`: stays `PENDING_VERIFICATION` |

Absence of a finding is not evidence of a fix, so a rule that did not evaluate
the resource can never close an action. A `VERIFICATION_FAILED` action can still
be verified by a later rescan.

## Not yet in scope

- HTTP routes and UI for proposing and approving.
- Generating proposals from findings automatically.
- Separation of duties (requiring approver and proposer to differ).
- Authentication of the `actor` strings; callers pass an identity the API layer
  has already authenticated.
