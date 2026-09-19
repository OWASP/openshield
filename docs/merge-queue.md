# Merge Queue

OpenShield uses Mergify to run a serial merge queue on the `dev` branch.
GitHub Actions remains the CI system. Mergify reads pull-request state,
waits for all conditions to be met, rebases each PR onto the current `dev`
HEAD, and merges it only after CI passes on the updated state.

This configuration is inactive until the Mergify GitHub App is installed
and authorized for this repository. The `.mergify.yml` file has no effect
before installation.

## Eligibility

The queue applies only to pull requests that target the `dev` branch.
PRs targeting any other branch are not affected by this configuration.

A pull request enters the queue automatically when all of the following
are true:

- The PR targets the `dev` branch
- `CI Summary` check is successful (aggregates all jobs in `ci.yml`,
  including the Astro website build and rendered-site verification)
- `DCO sign-off` check is successful
- `dependency-review` check is successful
- `Analyze (python)` check is successful
- `Analyze (javascript)` check is successful
- `Terraform fmt / validate / plan` check is successful, or the PR does
  not touch any files under `infra/terraform/` (the check only runs for
  terraform-touching PRs, so a plain `check-success` condition would stall
  every other PR)
- At least one approving review exists and is current for the latest push
- If the PR touches `GOVERNANCE.md`, `MAINTAINERS.md`, `.mergify.yml`, or
  `docs/merge-queue.md`: at least two approving reviews, and the project
  lead (`@Vishnu2707`) must be one of the approvers (per GOVERNANCE.md §5)
- No active `CHANGES_REQUESTED` review exists
- All review conversations are resolved
- The pull request is not a draft
- The `blocked` label is not applied

Mergify processes one pull request at a time. It rebases the queued PR onto
the latest `dev` and runs CI again before merging, so the branch is always
tested against what is actually on `dev` at merge time.

`CI Summary` covers all jobs inside `ci.yml`. `Analyze (python)` and
`Analyze (javascript)` are the CodeQL per-job checks from `codeql.yml`;
they are gated separately because `codeql.yml` is a different workflow and
is not included in `CI Summary`. The external Semgrep app checks are
deliberately not gated: their coverage duplicates the `SAST (Semgrep)` job
already in `CI Summary`, and gating third-party app checks would stall the
queue if the app is ever uninstalled or its plan changes.

## Keeping a PR out of the queue

To prevent a PR from entering the queue while it is still in progress, either:

- Open it as a **draft**. Mergify will not queue it until you mark it ready
  for review.
- Apply the **`blocked` label**. This removes the PR from queue eligibility
  and also prevents it from merging even if it is already in the queue.
  Remove the label when the PR is ready to proceed.

## Declaring dependencies

If your PR depends on another PR or issue merging first, declare it in the
pull request description:

```
Depends-On: #123
```

Use one `Depends-On:` line per dependency. The PR can enter the queue
immediately, but Mergify holds it there until every declared dependency has
merged. Once all dependencies are satisfied, Mergify re-evaluates the PR
against the latest `dev` state and proceeds.

Leave the placeholder as `none` when there are no dependencies:

```
Depends-On: none
```

Do not delete the section. It makes dependency state visible to reviewers.

If a dependency PR is closed without merging, Mergify will hold your PR
indefinitely. To unblock it, edit the PR description and remove or replace
the `Depends-On:` line for that closed PR, then update the branch to
trigger re-evaluation.

## awaiting-author label and inactive-author process

Mergify applies `awaiting-author` automatically when a reviewer submits a
`CHANGES_REQUESTED` review. No manual step is needed.

If the author remains inactive after the label is applied:

1. After five working days, a maintainer notes the inactivity in the PR
   and may take over the branch, open a replacement PR, or remove a
   dependency that review confirms is unnecessary.
2. The decision is recorded in the PR before changing ownership or
   dependency state.

## Approval freshness

When a contributor pushes a new commit to a dev-targeted PR, all existing
approvals are dismissed automatically. `CHANGES_REQUESTED` reviews are NOT
dismissed: a reviewer's objection survives the push and continues to block
`#changes-requested-reviews-by=0` until the reviewer themselves re-reviews
and clears it, or a maintainer manually dismisses it via GitHub (see
inactive-reviewer process below).

This means every approval in `merge_conditions` always reflects the code
that will actually land on `dev`, and no blocking concern can be erased by
a push followed by a third-party approval.

If your PR gets rebased while waiting in the queue, expect your approval to
be dismissed and the PR to return to "needs review" state before it can
re-enter the queue.

**For reviewers:** use inline conversation threads for every blocking
concern, not just the review summary body. Inline threads survive approval
dismissal and block independently via `#review-threads-unresolved=0`, so
your concern is protected even if another reviewer later approves.

## Inactive-reviewer process

If a reviewer left `CHANGES_REQUESTED` and has not responded after the
contributor pushed a fix:

1. After three working days with no response, the contributor tags the
   reviewer and a maintainer in the PR comments.
2. If there is still no response after two more working days, a maintainer
   reads the original review, verifies that the fix addresses the concern,
   and manually dismisses the stale review via GitHub with a comment
   recording what was checked and why the fix is accepted.
3. The decision is recorded in the PR before any dismissal so the reasoning
   is auditable.

## Governance-policy changes

Changes to `GOVERNANCE.md`, `.mergify.yml`, or `docs/merge-queue.md` require
two approvals before they can merge through the queue. This matches the
project-lead plus one additional maintainer requirement in GOVERNANCE.md §5.

The queue enforces this via the condition:

```
or:
  - -files~=^(GOVERNANCE\.md|\.mergify\.yml|docs/merge-queue\.md)$
  - "#approved-reviews-by>=2"
```

For PRs that do not touch these files the left side is true and one approval
is sufficient. For PRs that do touch them, the left side is false, so two
approvals are required.

Governance-policy PRs may not auto-merge with only one approval regardless of
how many other checks pass. They follow the same queue path as all other PRs;
no separate manual merge step is needed once two approvals are in place.

### Validation scenarios

The following scenarios describe expected queue behavior. They can be verified
against a Mergify dry-run or by inspecting queue state on a real PR.

**Scenario 1: Blocking review with no inline thread, followed by unrelated push**

A reviewer submits `CHANGES_REQUESTED` with the concern in the review summary
body only (no inline thread). A contributor then pushes a fix commit.

Expected behavior:
- The `CHANGES_REQUESTED` review survives the push (`changes_requested: false`
  in `dismiss_reviews` means only `APPROVED` reviews are dismissed).
- The `#changes-requested-reviews-by=0` condition remains unsatisfied.
- The PR cannot enter the queue or merge until the original reviewer re-reviews
  and clears the `CHANGES_REQUESTED` verdict, or a maintainer dismisses it
  following the inactive-reviewer process.
- A third party approving after the push does not clear the block.

**Scenario 2: Push after approval invalidates the stale approval**

A reviewer approves a PR. The contributor pushes one more commit.

Expected behavior:
- Mergify dismisses the approval automatically (the `dismiss stale approvals
  on new push` rule, `approved: true`).
- The PR exits the queue if it was already in it.
- `#approved-reviews-by>=1` becomes unsatisfied; the PR needs a fresh approval
  before it can re-enter the queue.

**Scenario 3: Governance-policy change with only one approval does not auto-merge**

A PR modifies `.mergify.yml` or `GOVERNANCE.md` and receives exactly one
approving review, with all CI checks green.

Expected behavior:
- The `or: [-files~=..., "#approved-reviews-by>=2"]` condition evaluates the
  left side as false (the PR does touch governance files).
- The right side (`#approved-reviews-by>=2`) is false because only one approval
  exists.
- The whole `or` condition is false; the PR does not enter the queue.
- A second approval from another maintainer or the project lead satisfies the
  condition and allows the PR to proceed through the normal queue path.

## GitHub branch protection

Mergify does not replace or weaken GitHub branch protection. It operates
on top of it. Any protection rules set directly in GitHub repository
settings remain the source of truth and are enforced independently of
Mergify.

## Pausing the queue

If the queue merges a PR that bypasses a protection or produces unexpected
behavior, a maintainer pauses queue operation immediately and records the
incident in issue #334 before resuming.
