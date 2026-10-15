"""Safety checks for the signed release workflow."""

from pathlib import Path

import yaml


WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "release.yml"


def _workflow():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_release_workflow_has_keyless_attestation_permissions():
    assert _workflow()["permissions"] == {
        "contents": "write",
        "id-token": "write",
        "attestations": "write",
    }


def test_release_requires_verified_annotated_tag():
    steps = _workflow()["jobs"]["release"]["steps"]
    verification = next(step for step in steps if step.get("id") == "verify")
    assert verification["run"] == "python3 scripts/release_integrity.py verify"
    assert steps.index(verification) < next(i for i, step in enumerate(steps) if step["name"] == "Install Syft")


def test_release_attests_every_distributed_manifest():
    source = WORKFLOW.read_text(encoding="utf-8")
    action = "actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373"
    assert source.count(action) == 5
    assert "openshield-${{ env.TAG }}.tar.gz" in source
    assert "openshield-${{ env.TAG }}-sbom.cyclonedx.json" in source
    assert "subject-path: dist/SHA256SUMS" in source
    assert "subject-path: dist/*.whl" in source
    assert "subject-path: dist/owasp_openshield-*.tar.gz" in source


def test_release_artifact_is_deterministic_and_checksums_are_published():
    source = WORKFLOW.read_text(encoding="utf-8")
    assert "git archive --format=tar" in source
    assert "gzip --no-name" in source
    assert "sha256sum" in source
    assert "files: dist/*" in source


def test_pypi_publication_requires_explicit_owner_readiness_gate():
    job = _workflow()["jobs"]["pypi"]
    assert job["if"] == "${{ vars.PYPI_TRUSTED_PUBLISHING_READY == 'true' }}"
    assert job["environment"]["name"] == "pypi"
    assert job["permissions"] == {"id-token": "write"}
