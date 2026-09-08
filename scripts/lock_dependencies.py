"""Generate or verify the Python 3.11/Linux dependency locks without upgrading by default."""

from __future__ import annotations

import argparse
from importlib.metadata import version
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LOCKS = ("requirements", "requirements-dev", "requirements-lock")


def compile_locks(root: Path, upgrade: bool = False) -> None:
    for name in LOCKS:
        command = [
            sys.executable,
            "-m",
            "piptools",
            "compile",
            "--generate-hashes",
            "--allow-unsafe",
            "--strip-extras",
            "--no-header",
            "--no-annotate",
            "--no-emit-index-url",
            "--no-emit-trusted-host",
            "--quiet",
            "--pip-args=--only-binary=:all:",
            f"--output-file={name}.txt",
            f"{name}.in",
        ]
        if upgrade:
            command.append("--upgrade")
        subprocess.run(command, cwd=root, check=True)


def check_locks(root: Path) -> list[str]:
    # Seed the resolver with the committed locks so a new upstream release
    # alone cannot make CI fail. Re-resolve changed inputs without editing them.
    with tempfile.TemporaryDirectory(prefix="openshield-lock-check-") as directory:
        scratch = Path(directory)
        for name in LOCKS:
            for suffix in (".in", ".txt"):
                shutil.copyfile(root / f"{name}{suffix}", scratch / f"{name}{suffix}")
        compile_locks(scratch)
        return [name for name in LOCKS if (root / f"{name}.txt").read_bytes() != (scratch / f"{name}.txt").read_bytes()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--upgrade", action="store_true", help="Explicitly refresh all allowed versions")
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 11) or sys.platform != "linux":
        parser.error("Generate/check locks using Python 3.11 on Linux (the supported runtime).")
    if version("pip-tools") != "7.5.3" or version("pip") != "26.1.2":
        parser.error("Install requirements-lock.txt in an isolated virtual environment first.")
    if args.check:
        stale = check_locks(ROOT)
        if stale:
            print("Stale dependency locks: " + ", ".join(stale), file=sys.stderr)
            return 1
        print("Dependency locks match their inputs.")
    else:
        compile_locks(ROOT, args.upgrade)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
