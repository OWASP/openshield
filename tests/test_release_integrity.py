"""Offline release tests. No live registry, GitHub mutation or signing keys."""

import io
import json
from pathlib import Path
import subprocess

import pytest
import yaml

from scripts import release_integrity as gate

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
TAG_OBJECT = "b" * 40
IMAGE = "ghcr.io/owasp/openshield"
DIGEST = "sha256:" + "c" * 64


@pytest.fixture
def environment():
    return {
        "GITHUB_REPOSITORY": gate.REPOSITORY,
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF": "refs/tags/v1.2.3",
        "GITHUB_SHA": COMMIT,
        "RELEASE_TAG": "v1.2.3",
        "RELEASE_COMMIT": COMMIT,
        "EXPECTED_TAG_OBJECT": TAG_OBJECT,
    }


class Commands:
    def __init__(self):
        self.calls = []
        self.ref = {"object": {"type": "tag", "sha": TAG_OBJECT}}
        self.signed = {
            "tag": "v1.2.3",
            "verification": {"verified": True, "reason": "valid"},
            "object": {"type": "commit", "sha": COMMIT},
        }
        self.head = COMMIT
        self.not_on_main = False

    def __call__(self, args):
        self.calls.append(args)
        if args[:2] == ["gh", "api"]:
            assert len(args) == 3  # Read-only GET, never a publication operation.
            return json.dumps(self.ref if "/git/ref/" in args[2] else self.signed)
        if args[:2] == ["git", "rev-parse"]:
            return self.head
        if args[:2] == ["git", "merge-base"] and self.not_on_main:
            raise subprocess.CalledProcessError(1, args)
        assert args[:2] in (["git", "fetch"], ["git", "merge-base"])
        return ""


@pytest.mark.parametrize("container", [False, True])
def test_verified_source_and_container_gates(environment, container):
    if not container:
        environment.pop("RELEASE_COMMIT")
        environment.pop("EXPECTED_TAG_OBJECT")
    run = Commands()
    assert gate.verify(environment, run) == {
        "release_tag": "v1.2.3",
        "release_commit": COMMIT,
        "tag_object": TAG_OBJECT,
    }
    assert run.calls[-1] == ["git", "merge-base", "--is-ancestor", COMMIT, "refs/remotes/origin/main"]


@pytest.mark.parametrize(
    "key,value",
    [
        ("GITHUB_REPOSITORY", "someone/fork"),
        ("GITHUB_REPOSITORY", "openshield-org/openshield"),
        ("GITHUB_EVENT_NAME", "workflow_dispatch"),
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("GITHUB_REF", "refs/heads/main"),
        ("GITHUB_REF", "refs/tags/v1.2.4"),
        ("RELEASE_TAG", "v1.2.3; echo injected"),
        ("RELEASE_TAG", "v1.2.3\nextra=value"),
        ("RELEASE_TAG", "v01.2.3"),
        ("RELEASE_TAG", "v1.2.3-rc.1"),
        ("RELEASE_TAG", "v1"),
        ("GITHUB_SHA", "not-a-sha"),
        ("RELEASE_COMMIT", "d" * 40),
        ("EXPECTED_TAG_OBJECT", "bad"),
        ("EXPECTED_TAG_OBJECT", ""),
    ],
)
def test_invalid_context_rejected_before_commands(environment, key, value):
    environment[key] = value
    run = Commands()
    with pytest.raises(ValueError):
        gate.verify(environment, run)
    assert run.calls == []


@pytest.mark.parametrize(
    "case",
    [
        "lightweight",
        "moved",
        "unsigned",
        "invalid_reason",
        "truthy_string",
        "wrong_commit",
        "nested_tag",
        "wrong_tag",
        "wrong_checkout",
    ],
)
def test_invalid_evidence_rejected(environment, case):
    run = Commands()
    if case == "lightweight":
        run.ref["object"]["type"] = "commit"
    elif case == "moved":
        run.ref["object"]["sha"] = "d" * 40
    elif case == "unsigned":
        run.signed["verification"]["verified"] = False
    elif case == "invalid_reason":
        run.signed["verification"]["reason"] = "expired_key"
    elif case == "truthy_string":
        run.signed["verification"]["verified"] = "true"
    elif case == "wrong_commit":
        run.signed["object"]["sha"] = "e" * 40
    elif case == "nested_tag":
        run.signed["object"]["type"] = "tag"
    elif case == "wrong_tag":
        run.signed["tag"] = "v1.2.4"
    else:
        run.head = "f" * 40
    with pytest.raises(ValueError):
        gate.verify(environment, run)
    assert all(args[:2] != ["git", "merge-base"] for args in run.calls)


def test_signed_but_unmerged_commit_rejected(environment):
    run = Commands()
    run.not_on_main = True
    with pytest.raises(subprocess.CalledProcessError):
        gate.verify(environment, run)


@pytest.mark.parametrize("payload", ["not json", "null", "[]", "{}"])
def test_malformed_api_response_writes_no_outputs(environment, monkeypatch, tmp_path, payload):
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    output = tmp_path / "outputs"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setattr("sys.argv", ["release_integrity.py", "verify"])
    real_verify = gate.verify
    monkeypatch.setattr(gate, "verify", lambda env: real_verify(env, lambda _: payload))
    assert gate.main() == 1
    assert not output.exists()


def test_transport_failure_writes_no_outputs(monkeypatch, tmp_path):
    output = tmp_path / "outputs"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setattr("sys.argv", ["release_integrity.py", "verify"])

    def unavailable(_):
        raise subprocess.TimeoutExpired("gh api", 60)

    monkeypatch.setattr(gate, "verify", unavailable)
    assert gate.main() == 1
    assert not output.exists()


@pytest.mark.parametrize("on_main", [True, False])
def test_ancestry_against_real_local_git_history(tmp_path, environment, on_main):
    repo = tmp_path / "repo"
    remote = tmp_path / "remote.git"

    def git(*args):
        result = subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)
        return result.stdout.strip()

    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True)
    git("config", "user.name", "Offline test")
    git("config", "user.email", "test@example.invalid")
    git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-m", "base fixture")
    base = git("rev-parse", "HEAD")
    git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-m", "advance main fixture")
    git("remote", "add", "origin", str(remote))
    git("push", "origin", "main")  # local filesystem remote, never GitHub
    git("checkout", "--detach", base)
    if not on_main:
        git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-m", "unmerged fixture")
    commit = git("rev-parse", "HEAD")
    environment.update(GITHUB_SHA=commit, RELEASE_COMMIT=commit)
    metadata = Commands()
    metadata.signed["object"]["sha"] = commit

    def run(args):
        return metadata(args) if args[0] == "gh" else git(*args[1:])

    if on_main:
        assert gate.verify(environment, run)["release_commit"] == base
    else:
        with pytest.raises(subprocess.CalledProcessError):
            gate.verify(environment, run)


@pytest.mark.parametrize(
    "values",
    [
        None,
        {},
        [],
        [123],
        [f"other/image@{DIGEST}"],
        [f"{IMAGE}@sha256:bad"],
        [f"{IMAGE}@{DIGEST}", f"{IMAGE}@sha256:{'d' * 64}"],
        [f"{IMAGE}.attacker.invalid@{DIGEST}"],
    ],
)
def test_missing_ambiguous_or_foreign_digest_rejected(values):
    with pytest.raises(ValueError):
        gate.registry_digest(values, IMAGE)


def test_exact_repository_digest_selected():
    assert gate.registry_digest([f"other/image@{DIGEST}", f"{IMAGE}@{DIGEST}"], IMAGE) == DIGEST


@pytest.mark.parametrize("expected,success", [(DIGEST, True), ("sha256:" + "e" * 64, False)])
def test_promotion_digest_checked_before_outputs(monkeypatch, tmp_path, expected, success):
    output = tmp_path / "outputs"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setattr("sys.argv", ["release_integrity.py", "digest", "--image", IMAGE, "--expect", expected])
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps([f"{IMAGE}@{DIGEST}"])))
    assert gate.main() == (0 if success else 1)
    assert output.exists() == success
    if success:
        assert output.read_text() == f"digest={DIGEST}\n"


def workflows():
    return tuple(
        yaml.safe_load((ROOT / ".github/workflows" / name).read_text()) for name in ("release.yml", "docker.yml")
    )


def test_no_independent_container_publication_trigger():
    source, container = workflows()
    assert set(container.get("on", container.get(True))) == {"workflow_call"}
    call = source["jobs"]["container"]
    assert call["needs"] == "release"
    assert call["uses"] == "./.github/workflows/docker.yml"
    assert "if" not in call  # default success(); never always() after failed source release
    assert call["with"]["release_commit"] == "${{ needs.release.outputs.release_commit }}"
    assert call["with"]["tag_object"] == "${{ needs.release.outputs.tag_object }}"
    assert "vars.CONTAINER_RELEASE_ENABLED == 'true'" in container["jobs"]["docker"]["if"]


def test_scan_and_attestations_gate_version_publication():
    _, workflow = workflows()
    steps = workflow["jobs"]["docker"]["steps"]
    names = [step["name"] for step in steps]
    order = [
        "Reverify signed source before build",
        "Build once and save the exact image",
        "Scan saved image before registry publication",
        "Generate image SBOM from scanned archive",
        "Reverify tag before any registry write",
        "Log in to GitHub Container Registry",
        "Push scanned candidate and capture registry digest",
        "Attest image provenance by digest",
        "Attest image SBOM by the same digest",
        "Verify both attestations before version promotion",
        "Promote verified image without rebuilding",
    ]
    assert [names.index(name) for name in order] == sorted(names.index(name) for name in order)
    for step in steps[:-1]:
        assert not step.get("continue-on-error", False)
        assert "if" not in step  # every publication step fails closed
    runs = "\n".join(step.get("run", "") for step in steps)
    assert runs.count("docker build ") == 1
    assert 'syft "docker-archive:$RUNNER_TEMP/image.tar"' in runs
    assert '--image "$IMAGE_NAME" --expect "$DIGEST"' in runs
    scan = next(step for step in steps if step["name"] == order[2])
    assert scan["with"]["input"] == "${{ runner.temp }}/image.tar"
    assert scan["with"]["exit-code"] == "1"
    assert scan["with"]["severity"] == "CRITICAL,HIGH"


def test_attestations_bind_digest_workflow_and_source():
    _, workflow = workflows()
    steps = workflow["jobs"]["docker"]["steps"]
    attest = [step for step in steps if step.get("uses", "").startswith("actions/attest")]
    assert len(attest) == 2
    for step in attest:
        assert step["with"]["subject-digest"] == "${{ steps.push.outputs.digest }}"
        assert step["with"]["subject-name"] == "${{ env.IMAGE_NAME }}"
        assert step["with"]["push-to-registry"] is True
    verify = next(step["run"] for step in steps if step["name"] == "Verify both attestations before version promotion")
    assert verify.count('gh attestation verify "oci://${IMAGE_NAME}@${DIGEST}"') == 2
    assert verify.count('--source-digest "$RELEASE_COMMIT" --source-ref "refs/tags/$RELEASE_TAG"') == 2
    assert verify.count('--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/docker.yml"') == 2
    assert "--predicate-type https://cyclonedx.org/bom" in verify


def test_actions_pinned_and_checkout_token_not_persisted():
    _, workflow = workflows()
    steps = workflow["jobs"]["docker"]["steps"]
    for step in steps:
        if "uses" in step:
            assert gate.SHA.fullmatch(step["uses"].split("@", 1)[1])
    assert steps[0]["with"]["ref"] == "${{ inputs.release_commit }}"
    assert steps[0]["with"]["persist-credentials"] is False


def test_workflow_shell_blocks_parse_without_execution():
    source, container = workflows()
    for workflow in (source, container):
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                if "run" in step:
                    result = subprocess.run(["bash", "-n"], input=step["run"], text=True, capture_output=True)
                    assert result.returncode == 0, f"{step['name']}: {result.stderr}"


def test_source_archive_uses_verified_commit_and_rechecks_before_publish():
    source, _ = workflows()
    steps = source["jobs"]["release"]["steps"]
    build = next(step for step in steps if step["name"] == "Build deterministic release artifacts")
    assert build["env"]["RELEASE_COMMIT"] == "${{ steps.verify.outputs.release_commit }}"
    assert '"$RELEASE_COMMIT"' in build["run"]
    names = [step["name"] for step in steps]
    assert names.index("Reverify source before release publication") < names.index("Publish release")
