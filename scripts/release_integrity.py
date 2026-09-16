"""Read-only release preflight and exact registry-digest validation."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPOSITORY = "OWASP/openshield"
SHA = re.compile(r"[0-9a-f]{40}")
TAG = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")


def command(args: list[str]) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=60).stdout.strip()


def verify(environment: dict[str, str], run=command) -> dict[str, str]:
    tag = environment.get("RELEASE_TAG", "")
    commit = environment.get("GITHUB_SHA", "")
    expected_tag = environment.get("EXPECTED_TAG_OBJECT", "")
    if environment.get("GITHUB_REPOSITORY") != REPOSITORY:
        raise ValueError("Publication is restricted to the OpenShield repository")
    if not TAG.fullmatch(tag):
        raise ValueError("Use a stable vMAJOR.MINOR.PATCH release tag")
    if environment.get("GITHUB_EVENT_NAME") != "push" or environment.get("GITHUB_REF") != f"refs/tags/{tag}":
        raise ValueError("Publication requires the matching tag-push event")
    if not SHA.fullmatch(commit) or environment.get("RELEASE_COMMIT", commit) != commit:
        raise ValueError("The requested commit must match the tag event")
    if (expected_tag or "RELEASE_COMMIT" in environment) and not SHA.fullmatch(expected_tag):
        raise ValueError("Invalid expected annotated-tag object")

    ref = json.loads(run(["gh", "api", f"repos/{REPOSITORY}/git/ref/tags/{tag}"]))
    obj = ref.get("object", {})
    tag_object = obj.get("sha", "")
    if obj.get("type") != "tag" or not SHA.fullmatch(tag_object):
        raise ValueError("A signed annotated tag is required, not a lightweight tag")
    if expected_tag and tag_object != expected_tag:
        raise ValueError("The tag moved after the source-release gate")
    signed = json.loads(run(["gh", "api", f"repos/{REPOSITORY}/git/tags/{tag_object}"]))
    verification = signed.get("verification", {})
    if verification.get("verified") is not True or verification.get("reason") != "valid":
        raise ValueError("GitHub did not verify the tag signature as valid")
    target = signed.get("object", {})
    if signed.get("tag") != tag or target.get("type") != "commit" or target.get("sha") != commit:
        raise ValueError("The signed tag must directly identify the event commit")
    if run(["git", "rev-parse", "HEAD"]) != commit:
        raise ValueError("Checkout differs from the verified commit")
    run(["git", "fetch", "--no-tags", "origin", "+refs/heads/main:refs/remotes/origin/main"])
    # Nonzero exit, including transport/repository errors, prevents publication.
    run(["git", "merge-base", "--is-ancestor", commit, "refs/remotes/origin/main"])
    return {"release_tag": tag, "release_commit": commit, "tag_object": tag_object}


def registry_digest(values, image: str) -> str:
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError("RepoDigests must be a list of strings")
    prefix = f"{image}@"
    matches = {value[len(prefix) :] for value in values if value.startswith(prefix)}
    if len(matches) != 1:
        raise ValueError("Expected exactly one digest for the published repository")
    digest = matches.pop()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("Invalid registry manifest digest")
    return digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    sub.add_parser("verify")
    digest_parser = sub.add_parser("digest")
    digest_parser.add_argument("--image", required=True)
    digest_parser.add_argument("--expect")
    args = parser.parse_args()
    try:
        if args.operation == "verify":
            result = verify(dict(os.environ))
        else:
            digest = registry_digest(json.load(sys.stdin), args.image)
            if args.expect and digest != args.expect:
                raise ValueError("Promotion changed the verified digest")
            result = {"digest": digest}
        if output := os.environ.get("GITHUB_OUTPUT"):
            with Path(output).open("a", encoding="utf-8") as handle:
                for key, value in result.items():
                    handle.write(f"{key}={value}\n")
        print(json.dumps(result))
        return 0
    except (ValueError, TypeError, AttributeError, OSError, subprocess.SubprocessError) as exc:
        print(f"Release rejected: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
