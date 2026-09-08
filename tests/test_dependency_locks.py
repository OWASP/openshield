"""Offline regression checks; actual resolution and pip hash enforcement run in CI."""

from pathlib import Path
import hashlib
import re
import subprocess
import sys
import zipfile

import pytest
import yaml

from scripts import lock_dependencies as locks

ROOT = Path(__file__).resolve().parents[1]


def pins(name):
    text = (ROOT / f"{name}.txt").read_text().replace("\\\n", " ")
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line == "--only-binary :all:":
            continue
        match = re.fullmatch(r"([a-z0-9-]+)==([^\s;]+)(?:\s+--hash=sha256:[a-f0-9]{64})+", line)
        assert match, f"Unpinned/unhashed or unsupported requirement: {line}"
        assert match[1] not in result
        result[match[1]] = match[2]
    assert result
    return result


@pytest.mark.parametrize("name", locks.LOCKS)
def test_all_dependencies_are_exactly_pinned_and_hashed(name):
    pins(name)


def test_development_uses_production_versions_without_shipping_test_tools():
    runtime = pins("requirements")
    dev = pins("requirements-dev")
    assert all(dev.get(name) == version for name, version in runtime.items())
    assert {"pytest", "pytest-cov", "coverage", "ruff"} <= dev.keys()
    assert not {"pytest", "pytest-cov", "coverage", "ruff", "pip-tools"} & runtime.keys()


def test_ci_checks_locks_and_installs_the_development_lock():
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    assert "rule-validation" in jobs["ci-summary"]["needs"]
    rule_steps = "\n".join(step.get("run", "") for step in jobs["rule-validation"]["steps"])
    assert "scripts/lock_dependencies.py --check" in rule_steps
    assert "--require-hashes --only-binary=:all: -r requirements-lock.txt" in rule_steps
    for job in ("lint", "backend-tests"):
        steps = "\n".join(step.get("run", "") for step in jobs[job]["steps"])
        assert "--require-hashes --only-binary=:all: -r requirements-dev.txt" in steps


def test_production_install_paths_require_hashes_and_wheels():
    flags = "--require-hashes --only-binary=:all: -r requirements.txt"
    assert flags in (ROOT / "Dockerfile").read_text()
    services = yaml.safe_load((ROOT / "render.yaml").read_text())["services"]
    assert len(services) == 4
    assert all(flags in service["buildCommand"] for service in services)
    assert (ROOT / ".python-version").read_text().strip() == "3.11"


def test_compile_is_hash_checked_wheel_only_and_runtime_first(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(locks.subprocess, "run", lambda command, **kwargs: calls.append((command, kwargs)))
    locks.compile_locks(tmp_path)
    assert [command[-1] for command, _ in calls] == [f"{name}.in" for name in locks.LOCKS]
    for command, kwargs in calls:
        assert "--generate-hashes" in command
        assert "--pip-args=--only-binary=:all:" in command
        assert "--upgrade" not in command
        assert kwargs == {"cwd": tmp_path, "check": True}
    calls.clear()
    locks.compile_locks(tmp_path, upgrade=True)
    assert all("--upgrade" in command for command, _ in calls)


@pytest.mark.parametrize("changed", [False, True])
def test_check_detects_drift_without_modifying_checkout(monkeypatch, tmp_path, changed):
    for name in locks.LOCKS:
        (tmp_path / f"{name}.in").write_text("input\n")
        (tmp_path / f"{name}.txt").write_text("committed\n")

    def fake_compile(scratch):
        assert scratch != tmp_path
        assert (scratch / "requirements.txt").read_text() == "committed\n"
        if changed:
            (scratch / "requirements.txt").write_text("updated\n")

    monkeypatch.setattr(locks, "compile_locks", fake_compile)
    assert locks.check_locks(tmp_path) == (["requirements"] if changed else [])
    assert all((tmp_path / f"{name}.txt").read_text() == "committed\n" for name in locks.LOCKS)


def test_check_fails_closed_on_resolution_error(monkeypatch, tmp_path):
    for name in locks.LOCKS:
        for suffix in (".in", ".txt"):
            (tmp_path / f"{name}{suffix}").write_text("input\n")

    def fail(_):
        raise locks.subprocess.CalledProcessError(1, "pip-compile")

    monkeypatch.setattr(locks, "compile_locks", fail)
    with pytest.raises(locks.subprocess.CalledProcessError):
        locks.check_locks(tmp_path)


@pytest.mark.parametrize("tampered", [False, True])
def test_pip_accepts_matching_hash_and_rejects_tampering_offline(tmp_path, tampered):
    wheel = tmp_path / "lock_probe-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("lock_probe-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: lock-probe\nVersion: 1.0\n")
        archive.writestr("lock_probe-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\nTag: py3-none-any\n")
        archive.writestr("lock_probe-1.0.dist-info/RECORD", "")
    digest = "0" * 64 if tampered else hashlib.sha256(wheel.read_bytes()).hexdigest()
    requirements = tmp_path / "probe.txt"
    requirements.write_text(f"lock-probe==1.0 --hash=sha256:{digest}\n")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "download",
            "--disable-pip-version-check",
            "--no-index",
            "--no-deps",
            "--require-hashes",
            "--only-binary=:all:",
            "--find-links",
            str(tmp_path),
            "--dest",
            str(tmp_path / "download"),
            "-r",
            str(requirements),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if tampered:
        assert result.returncode != 0
        assert "DO NOT MATCH THE HASHES" in result.stderr
    else:
        assert result.returncode == 0, result.stderr
