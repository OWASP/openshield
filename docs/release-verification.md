# Verifying OpenShield Releases

For the current OWASP-hosted container workflow, see
[container release integrity](container-release-integrity.md), including owner
opt-in, the new GHCR namespace and digest verification. The commands below retain
the historical source-artifact identity for releases from `openshield-org`;
for new OWASP-hosted source releases substitute `OWASP/openshield` in both
`--repo` and `--signer-workflow`.

OpenShield release artifacts are produced only from a GitHub-verified signed
annotated tag. GitHub Actions generates a deterministic source archive, a
CycloneDX SBOM and SHA-256 checksums, then creates identity-bound Sigstore
provenance attestations before uploading the files to the release.

## Verify checksums

Download all release assets into one directory, then run:

```bash
sha256sum --check SHA256SUMS
```

## Verify provenance

Install the GitHub CLI and verify each artifact against this repository:

```bash
gh attestation verify openshield-vX.Y.Z.tar.gz \
  --repo openshield-org/openshield \
  --signer-workflow openshield-org/openshield/.github/workflows/release.yml

gh attestation verify openshield-vX.Y.Z-sbom.cyclonedx.json \
  --repo openshield-org/openshield \
  --signer-workflow openshield-org/openshield/.github/workflows/release.yml

gh attestation verify SHA256SUMS \
  --repo openshield-org/openshield \
  --signer-workflow openshield-org/openshield/.github/workflows/release.yml
```

Successful verification proves that the artifact digest was attested by the
OpenShield release workflow for this public repository. It does not mean that
GitHub or Sigstore audited the source code.

## Maintainer release procedure

1. Confirm the release commit is on the approved `main` history and CI passes.
2. Create a signed annotated tag: `git tag -s vX.Y.Z -m "OpenShield vX.Y.Z"`.
   SSH signing may be used when Git is configured with `gpg.format=ssh`.
3. Verify locally with `git tag -v vX.Y.Z` using the project's trusted signer
   configuration.
4. Push only the tag: `git push origin vX.Y.Z`.
5. The workflow independently asks GitHub to verify the tag signature. A
   lightweight or unverified tag fails before artifacts are produced.
6. After publication, download and verify every asset using the commands above.

Existing historical lightweight tags are not retroactively described as signed.
