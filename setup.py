"""Derive distribution version from the signed release tag (or a dev checkout)."""

import os
import re
import subprocess
from email.parser import Parser
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py


class CliBuildPy(build_py):
    """Keep hosted worker entry points out of the standalone distribution."""

    def find_package_modules(self, package, package_dir):
        modules = super().find_package_modules(package, package_dir)
        if package == "scanner":
            return [item for item in modules if item[1] not in {"worker", "enrichment_worker"}]
        return modules


def version() -> str:
    metadata = Path(__file__).parent / "PKG-INFO"
    if metadata.exists() and not (Path(__file__).parent / ".git").exists():
        return Parser().parsestr(metadata.read_text(encoding="utf-8"))["Version"]
    tag = os.environ.get("RELEASE_TAG")
    if tag:
        if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
            raise ValueError("RELEASE_TAG must be a vMAJOR.MINOR.PATCH tag")
        tagged_commit = subprocess.check_output(["git", "rev-parse", f"{tag}^{{commit}}"], text=True).strip()
        current_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        if tagged_commit != current_commit:
            raise ValueError(f"RELEASE_TAG {tag} does not point to checked-out commit")
        return tag[1:]
    try:
        description = subprocess.check_output(
            ["git", "describe", "--tags", "--match", "v[0-9]*", "--long", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        match = re.fullmatch(r"v(\d+\.\d+\.\d+)-(\d+)-g([0-9a-f]+)", description)
        if match:
            base, distance, commit = match.groups()
            if int(distance) == 0:
                return base
            major, minor, patch = map(int, base.split("."))
            return f"{major}.{minor}.{patch + 1}.dev{distance}+g{commit}"
    except (OSError, subprocess.CalledProcessError):
        pass
    if metadata.exists():
        return Parser().parsestr(metadata.read_text(encoding="utf-8"))["Version"]
    raise RuntimeError("A git release tag or source archive PKG-INFO is required to determine version")


setup(version=version(), cmdclass={"build_py": CliBuildPy})
