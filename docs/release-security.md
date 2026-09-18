# Release Security and Verification

## Current process

Stable version tags trigger `.github/workflows/release.yml`, which verifies a
signed annotated tag and its commit's `main` ancestry, then creates and attests
the source archive, CycloneDX SBOM and checksum manifest before publication.
The dependent container workflow is owner-opt-in and scans the built image
before publishing a candidate, binds provenance/SBOM to its digest, and verifies
both before version promotion. Release actions are pinned to specific commits.
See [container release integrity](container-release-integrity.md) for the OWASP
registry transition, trust boundaries and first-release validation requirements.

## Required signing process

OpenShield must not mark the OpenSSF `signed_releases` criterion Met until the
following process is implemented and exercised for a real release:

1. Build a deterministic source or distribution archive from the reviewed tag.
2. Generate SHA-256 checksums and a cryptographic signature or keyless Sigstore
   attestation for each distributed artifact and its SBOM.
3. Keep signing authority separate from the public download location. A keyless
   workflow must bind the identity, repository, workflow and commit in the
   transparency record.
4. Upload artifacts, checksums, signatures/attestations and verification
   instructions to the release.
5. Verify the published artifacts in a separate CI step before announcing the
   release.
6. Create important release tags as signed annotated tags, or document why the
   artifact-attestation mechanism provides the authoritative release identity.

The project lead must approve the signing model and access policy before this is
automated. Existing `v0.1.0` and `v0.3.0` tags are lightweight tags and do not
by themselves satisfy signed-release requirements.

## User verification target

The final workflow must provide copyable verification commands that validate
the artifact digest, signer identity, repository and workflow identity. Those
commands will replace this section once the signing mechanism is selected and
tested.
