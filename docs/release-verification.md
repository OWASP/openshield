# Verifying OpenShield Releases

For the OWASP-hosted container workflow, see
[container release integrity](container-release-integrity.md), including owner
opt-in, the GHCR namespace and digest verification. Historical releases from
`openshield-org` require that repository identity in the verification command;
the examples here apply to new `OWASP/openshield` releases.

OpenShield release artifacts are produced only from a GitHub-verified signed
annotated tag. GitHub Actions generates a deterministic source archive, a
CycloneDX SBOM, Python wheel and source distribution, and SHA-256 checksums,
then creates identity-bound Sigstore provenance attestations before uploading
the files to the release.

## Verify checksums

Download all release assets into one directory, then run:

```bash
sha256sum --check SHA256SUMS
```

## Verify provenance

Install the GitHub CLI and verify each artifact against this repository:

```bash
gh attestation verify openshield-vX.Y.Z.tar.gz \
  --repo OWASP/openshield \
  --signer-workflow OWASP/openshield/.github/workflows/release.yml

gh attestation verify openshield-vX.Y.Z-sbom.cyclonedx.json \
  --repo OWASP/openshield \
  --signer-workflow OWASP/openshield/.github/workflows/release.yml

gh attestation verify SHA256SUMS \
  --repo OWASP/openshield \
  --signer-workflow OWASP/openshield/.github/workflows/release.yml

gh attestation verify owasp_openshield-X.Y.Z-py3-none-any.whl \
  --repo OWASP/openshield \
  --signer-workflow OWASP/openshield/.github/workflows/release.yml

gh attestation verify owasp_openshield-X.Y.Z.tar.gz \
  --repo OWASP/openshield \
  --signer-workflow OWASP/openshield/.github/workflows/release.yml
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
6. Before the first PyPI publication, a GitHub repository administrator creates
   the `pypi` environment with required reviewer protection. A PyPI project
   owner registers `OWASP/openshield`, `release.yml`, and the `pypi` environment
   as a Trusted Publisher. Recheck the `owasp-openshield` name immediately
   before the release; pending publisher registration does not reserve it.
   After verifying both settings, set the repository variable
   `PYPI_TRUSTED_PUBLISHING_READY` to `true`. Until then, the PyPI job is skipped
   so a tag cannot auto-create an unprotected environment. The GitHub Release
   still publishes its verified Python artifacts and checksums.
7. After publication, download and verify every GitHub Release asset using
   the commands above. Separately verify the PyPI project and install from
   the public index in a clean environment:

   ```bash
   python -m venv verify-venv
   verify-venv/bin/python -m pip install --index-url https://pypi.org/simple owasp-openshield==X.Y.Z
   verify-venv/bin/python -m pip check
   verify-venv/bin/openshield --version
   ```

   On Windows, use `verify-venv\Scripts\python.exe` and
   `verify-venv\Scripts\openshield.exe`. A successful GitHub Release job does
   not prove PyPI publication; inspect the separate `pypi` job.

Existing historical lightweight tags are not retroactively described as signed.
