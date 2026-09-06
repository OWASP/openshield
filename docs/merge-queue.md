# Merge Queue

OpenShield uses Mergify to run a serial merge queue on the `dev` branch.
GitHub Actions remains the CI system. Mergify reads pull-request state,
waits for all conditions to be met, rebases each PR onto the current `dev`
HEAD, and merges it only after CI passes on the updated state.

## Eligibility

A pull request enters the queue automatically when all of the following
are true:

- `CI Summary` check is successful (all GitHub Actions CI jobs passed)
- `DCO sign-off` check is successful
- `dependency-review` check is successful
- At least one approving review exists and is current for the latest push
- No active `CHANGES_REQUESTED` review exists
- All review conversations are resolved
- The pull request is not a draft
- The `blocked` label is not applied
- All declared dependencies have merged (see below)

Mergify processes one pull request at a time. It rebases the queued PR onto
the latest `dev` and runs CI again before merging, so the branch is always
tested against what is actually on `dev` at merge time.

## Declaring dependencies

If your PR depends on another PR or issue merging first, declare it in the
pull request description:

```
Depends-On: #123
```

Use one `Depends-On:` line per dependency. Mergify holds the PR in the queue
until every declared dependency is merged, then re-evaluates it against the
latest `dev` state.

Replace the placeholder in the PR template with `none` when there are no
dependencies:

```
Depends-On: none
```

Do not delete the section. It makes dependency state visible to reviewers.

## awaiting-author label

Mergify applies the `awaiting-author` label automatically when a reviewer
submits a `CHANGES_REQUESTED` review. The label is removed automatically
when all change requests are resolved.

Maintainers use this label to identify PRs that are blocked on the author
rather than on review availability.

## Inactive-author process

1. A maintainer applies `awaiting-author` after required changes are
   requested and the author is inactive for several days.
2. After five working days of inactivity, a maintainer may take over the
   branch, open a replacement PR, or remove a dependency that review
   confirms is unnecessary.
3. The decision is recorded in the PR before changing ownership or
   dependency state.

## GitHub branch protection

Mergify does not replace or weaken GitHub branch protection. It operates
on top of it. Any protection rules set directly in GitHub repository
settings remain the source of truth and are enforced independently of
Mergify.

## Pausing the queue

If the queue merges a PR that bypasses a protection or produces unexpected
behavior, a maintainer pauses queue operation immediately and records the
incident in issue #334 before resuming.
