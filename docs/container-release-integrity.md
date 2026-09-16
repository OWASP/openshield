# Container release integrity

This is the container-publication slice of #304. It does not claim that the
deployment topology, restore drills or complete enterprise release criteria are
finished. #336 separately addresses Python dependency locking.

## Release path

1. A stable `vMAJOR.MINOR.PATCH` tag push starts `release.yml`. Branch pushes,
   manual dispatch, lightweight tags, unverified signatures and nested tags do
   not qualify. The tag must directly identify the event/checkout commit, and
   that commit must be on the fetched `main` history.
2. Source artifacts are built from that immutable commit, attested and published
   through the signed-release job. The tag object is checked again before
   publishing source assets.
3. Only after the source job succeeds can its dependent reusable `docker.yml`
   job run. It requires owner opt-in via the repository variable
   `CONTAINER_RELEASE_ENABLED=true`.
4. The container gate rechecks repository, event, annotated-tag identity,
   signature, commit and `main` ancestry. It builds one Linux runner-native image
   and exports a Docker archive. Trivy scans that archive; Syft generates the
   image CycloneDX SBOM from the same archive, not from the source directory.
5. A passing scan and another tag check permit pushing a unique
   `candidate-RUN_ID-RUN_ATTEMPT` tag. The image ID must still match the built
   image. Both provenance and SBOM attestations bind to the exact registry
   manifest digest, using GitHub's keyless Sigstore-backed attestation actions.
6. Both attestations must verify against the repository, reusable signer
   workflow, source commit and tag ref. Only then is the existing local image
   tagged as `MAJOR.MINOR.PATCH` and pushed, without rebuilding. The promoted
   digest is checked against the attested digest. No moving `latest` or
   `MAJOR.MINOR` aliases are updated by this workflow.

All publishing steps use normal success dependencies. Scan errors, unavailable
verification services, ambiguous digests and failed attestations stop version
promotion. The last evidence-upload step may run on failure but cannot publish
an image. Trivy retains the current CI policy: fail on HIGH/CRITICAL findings
with available fixes (`ignore-unfixed: true`). This is not a claim that the
image has no vulnerabilities; no new ignore list is introduced.

## OWASP transfer and first-release approval

GitHub now identifies this repository as `OWASP/openshield`. New image releases
target **`ghcr.io/owasp/openshield`**, not the historical organization namespace.
Nothing in this change migrates, deletes or overwrites historical packages.

Before enabling the container job, an OWASP repository/package administrator must:

- Confirm that the repository's `GITHUB_TOKEN` may create/write this package
  and that its intended visibility and repository association are correct.
- Confirm the tag-creation/signing authority, `main` protections and review
  process. A GitHub-verified signature plus ancestry is not an independent
  authorization check on the signer; trusted tag writers and protected workflow
  files remain essential. Effective protection enforcement is tracked in #298.
- Review the workflow and approve a first-release verification plan, then set
  `CONTAINER_RELEASE_ENABLED=true`. Leaving it unset disables container
  publication; it does not disable source releases.
- Use a new signed stable release tag only after this workflow is promoted to
  `main` through the normal process. Old tags retain their old workflow code;
  this change is not a retroactive gate for historical workflows.
- Verify the published image and evidence below before announcing availability.

No administrator settings, tags, registry writes, release dispatches or deployments
are required to review this PR. Local unit tests use fake GitHub responses and
temporary local Git histories; they do not prove live OIDC/registry integration.
The first owner-authorized release must supply that operating evidence.

## Verify an image

Use the digest recorded in the successful workflow summary and
`container-release-evidence-RUN_ID-RUN_ATTEMPT` artifact. That artifact retains
the Trivy report, image SBOM, source identity and registry digest for 90 days.
Image attestations are also pushed to the registry and recorded by GitHub.

```bash
# Substitute the actual digest and source commit recorded by the release.
IMAGE=ghcr.io/owasp/openshield@sha256:ACTUAL_DIGEST
COMMIT=ACTUAL_SOURCE_COMMIT
TAG=vX.Y.Z

gh attestation verify "oci://$IMAGE" --repo OWASP/openshield \
  --signer-workflow OWASP/openshield/.github/workflows/docker.yml \
  --source-digest "$COMMIT" --source-ref "refs/tags/$TAG"

gh attestation verify "oci://$IMAGE" --repo OWASP/openshield \
  --signer-workflow OWASP/openshield/.github/workflows/docker.yml \
  --source-digest "$COMMIT" --source-ref "refs/tags/$TAG" \
  --predicate-type https://cyclonedx.org/bom
```

Authenticate to GHCR if required for package access. Use a current GitHub CLI
supporting these attestation flags. For reusable workflows, the reusable workflow
is the signer identity, not the caller. See the
[GitHub CLI verification reference](https://cli.github.com/manual/gh_attestation_verify).

## Failures and reruns

A failed run can leave an unpromoted candidate in GHCR: registry publication and
signing are not one atomic transaction. Never deploy a candidate or infer trust
from its tag. Verify the image by digest with both predicates. A source release
may already exist when the dependent container job fails; do not announce the
container until its job and verification finish.

Tag moves are rechecked before writes but are not locked atomically across GitHub
and GHCR. An administrator must restrict moving/deleting release tags. Reruns
can rebuild different bytes from mutable base/OS dependencies and can replace
the version tag; use a new release version for changed images and deploy pinned
digests. Digest pinning, not tag spelling, gives immutable consumption. Candidate
cleanup, immutable package-tag enforcement, multi-architecture publishing and
base-image reproducibility remain follow-up work.
