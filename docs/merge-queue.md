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
- `CI Summary` check is successful (aggregates all jobs in `ci.yml`)
- `DCO sign-off` check is successful
- `dependency-review` check is successful
- `CodeQL` check is successful
- `Analyze (python)` check is successful
- `Analyze (javascript)` check is successful
- At least one approving review exists and is current for the latest push
- No active `CHANGES_REQUESTED` review exists
- All review conversations are resolved
- The pull request is not a draft
- The `blocked` label is not applied

Mergify processes one pull request at a time. It rebases the queued PR onto
the latest `dev` and runs CI again before merging, so the branch is always
tested against what is actually on `dev` at merge time.

`CI Summary` covers all jobs inside `ci.yml`. Once PR #329 merges, it will
also include the Astro website build and rendered-site verification. CodeQL
runs in a separate workflow (`codeql.yml`) and is not part of `CI Summary`,
which is why it is listed explicitly above.

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

Approvals are dismissed automatically when a new commit is pushed to a
pull request targeting `dev`. This includes both author-pushed commits and
bot-created rebases (for example, when Mergify rebases your PR onto the
latest `dev` HEAD).

After each dismissal, at least one reviewer must re-approve before Mergify
can queue or merge the PR. This means the approval in `merge_conditions`
always reflects the state of the actual code that will land on `dev`.

If your PR gets rebased while waiting in the queue, expect your approval
to be dismissed and the PR to return to "needs review" state.

## GitHub branch protection

Mergify does not replace or weaken GitHub branch protection. It operates
on top of it. Any protection rules set directly in GitHub repository
settings remain the source of truth and are enforced independently of
Mergify.

## Pausing the queue

If the queue merges a PR that bypasses a protection or produces unexpected
behavior, a maintainer pauses queue operation immediately and records the
incident in issue #334 before resuming.
