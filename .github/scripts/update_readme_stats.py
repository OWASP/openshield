#!/usr/bin/env python3
"""Refresh the rule and playbook counts hardcoded in README.md.

README.md states the rule and playbook counts in its feature table and in two
nodes of its Mermaid architecture diagram. This script recomputes both counts
from scanner/rules/ and playbooks/cli/ and rewrites those four spots in place.

The website (including the Learn page) no longer needs this: it derives every
count from the repository at build time (website/src/lib/repoData.ts), so it
cannot drift. README.md is plain Markdown rendered by GitHub, so it is the one
place a number still has to be written down.

Usage:
    python .github/scripts/update_readme_stats.py          # rewrite README.md
    python .github/scripts/update_readme_stats.py --check  # report drift only

Nothing commits the result automatically: `dev` only accepts changes through
pull requests. The workflow runs --check after each merge and surfaces drift
as a warning, and whoever next touches README.md (or a maintainer) runs the
script and includes the diff in their PR.

Every substitution is tracked. If a pattern matches zero times - because the
surrounding wording changed - the script fails loudly instead of silently
leaving the file unchanged and exiting 0.
"""

import argparse
import re
import sys
from pathlib import Path
from typing import List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = REPO_ROOT / "scanner" / "rules"
PLAYBOOKS_DIR = REPO_ROOT / "playbooks" / "cli"
README_PATH = REPO_ROOT / "README.md"

# Rule modules are named az_<category>_<number>.py. Matching on that prefix is
# the same convention .github/workflows/ci.yml uses to discover rules, and it
# correctly excludes __init__.py and the shared _*_common.py helpers.
RULE_GLOB = "az_*.py"

RULE_ID_PATTERN = re.compile(r"^RULE_ID\s*=\s*[\"']([^\"']+)[\"']", re.MULTILINE)

# Exit code for --check when README.md is stale, distinct from real errors.
EXIT_STALE = 3


def count_rules() -> int:
    """Return the number of scanner rule modules that declare a RULE_ID."""
    if not RULES_DIR.is_dir():
        return 0
    return sum(1 for path in RULES_DIR.glob(RULE_GLOB) if RULE_ID_PATTERN.search(path.read_text(encoding="utf-8")))


def find_matching_playbooks() -> Tuple[int, List[str], List[str]]:
    """Return (playbook_count, missing_for_rules, orphan_playbook_files).

    Counting every *.sh file in playbooks/cli/ would also pick up shared helper
    scripts - e.g. review_enterprise_resilience.sh, which several fix_*.sh
    wrappers `exec` into rather than a playbook any single rule owns - silently
    inflating the count past rule_count and breaking the "every rule ships with
    a matching playbook" claim.

    Instead this mirrors the naming convention ci.yml's playbook_check step
    already enforces: playbooks/cli/fix_<rule filename stem>.sh for every
    counted rule module. missing_for_rules lists rule files whose expected
    playbook is absent; orphan_playbook_files lists *.sh files on disk that
    no counted rule expects (informational - shared helpers are expected to
    show up here and are not themselves an error).
    """
    if not RULES_DIR.is_dir() or not PLAYBOOKS_DIR.is_dir():
        return 0, [], []

    expected_names = set()
    missing_for_rules: List[str] = []
    for path in sorted(RULES_DIR.glob(RULE_GLOB)):
        if not RULE_ID_PATTERN.search(path.read_text(encoding="utf-8")):
            continue
        expected_name = f"fix_{path.stem}.sh"
        expected_names.add(expected_name)
        if not (PLAYBOOKS_DIR / expected_name).is_file():
            missing_for_rules.append(path.name)

    actual_names = {p.name for p in PLAYBOOKS_DIR.glob("*.sh")}
    orphan_playbook_files = sorted(actual_names - expected_names)
    playbook_count = len(expected_names) - len(missing_for_rules)
    return playbook_count, missing_for_rules, orphan_playbook_files


def apply_replacements(content: str, replacements: Tuple[Tuple[str, str, int], ...]) -> Tuple[str, List[str]]:
    """Apply each (name, pattern, value) substitution, tracking zero-match failures.

    A pattern that matches zero times means the surrounding wording no longer
    matches what this script expects - that is reported as a failure rather
    than silently leaving the file unchanged.
    """
    failures: List[str] = []
    for name, pattern, value in replacements:
        content, count = re.subn(pattern, rf"\g<1>{value}\g<2>", content)
        if count == 0:
            failures.append(name)
    return content, failures


def render_readme(content: str, rule_count: int, playbook_count: int) -> Tuple[str, List[str]]:
    """Return (updated_content, failed_pattern_names) for README.md."""
    # Anchored on the row label and the unit that follows the number, not on
    # the full prose. The wording of these rows (the category list, how the
    # scripts are described) is edited independently of the counts, and pinning
    # the whole sentence made this script fail on every unrelated reword while
    # the counts silently went stale. Losing the row itself, or the "Azure
    # security rules"/"(N playbooks)" shape, still fails loudly.
    feature_row = r"(\| \*\*Misconfiguration Scanner\*\* \| Runs )\d+( Azure security rules)"
    playbook_row = r"(\| \*\*Remediation Playbooks\*\* \|[^|]*\()\d+( playbooks\) \|)"
    mermaid_scanner = r'(C\["Scanner Engine\\n)\d+( Python rules"\])'
    mermaid_playbooks = r'(G\["Azure CLI Playbooks\\n)\d+( remediation scripts"\])'

    replacements: Tuple[Tuple[str, str, int], ...] = (
        ("feature table: Misconfiguration Scanner row", feature_row, rule_count),
        ("feature table: Remediation Playbooks row", playbook_row, playbook_count),
        ("Mermaid diagram: Scanner Engine node", mermaid_scanner, rule_count),
        ("Mermaid diagram: Azure CLI Playbooks node", mermaid_playbooks, playbook_count),
    )

    return apply_replacements(content, replacements)


def main(argv: List[str] | None = None) -> int:
    """Rewrite (or, with --check, verify) README.md counts; return an exit code."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help=f"do not write; exit {EXIT_STALE} if README.md counts are stale",
    )
    args = parser.parse_args(argv)

    if not README_PATH.is_file():
        print(f"Error: {README_PATH} not found", file=sys.stderr)
        return 1

    rule_count = count_rules()
    playbook_count, missing_playbooks, orphan_playbooks = find_matching_playbooks()

    if rule_count == 0 or playbook_count == 0:
        print("Error: found no rules or no playbooks; refusing to write zeroes into the docs.", file=sys.stderr)
        return 1

    if missing_playbooks:
        print(
            f"Error: {len(missing_playbooks)} rule(s) have no matching playbook file: {', '.join(missing_playbooks)}",
            file=sys.stderr,
        )
        return 1

    # Belt-and-suspenders: find_matching_playbooks() only counts playbooks
    # that resolve to a counted rule, so this should be unreachable once
    # missing_playbooks is empty. Failing loudly here catches a future bug in
    # that derivation rather than silently writing mismatched docs.
    if rule_count != playbook_count:
        print(
            f"Error: rule/playbook count mismatch (rules: {rule_count}, playbooks: "
            f"{playbook_count}); refusing to write inconsistent docs.",
            file=sys.stderr,
        )
        return 1

    if orphan_playbooks:
        print(
            f"Note: {len(orphan_playbooks)} playbook file(s) in playbooks/cli/ are not any rule's "
            f"matching playbook and are excluded from the count (expected for shared helpers "
            f"other playbooks exec into): {', '.join(orphan_playbooks)}",
            file=sys.stderr,
        )

    original = README_PATH.read_text(encoding="utf-8")
    updated, failures = render_readme(original, rule_count, playbook_count)

    if failures:
        print(
            "Error: the following README.md patterns matched zero times. The surrounding "
            "wording has likely changed and this script needs updating to match:",
            file=sys.stderr,
        )
        for name in failures:
            print(f"  - {name}", file=sys.stderr)
        return 1

    if updated == original:
        print(f"README.md statistics already current (rules: {rule_count}, playbooks: {playbook_count}).")
        return 0

    if args.check:
        print(
            f"README.md statistics are stale; repository now has {rule_count} rules and "
            f"{playbook_count} playbooks. Run: python .github/scripts/update_readme_stats.py"
        )
        return EXIT_STALE

    README_PATH.write_text(updated, encoding="utf-8")
    print(f"Updated README.md - rules: {rule_count}, playbooks: {playbook_count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
