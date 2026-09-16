#!/usr/bin/env python3
"""Refresh the rule/playbook/severity statistics in the Learn page and README.

docs/learn/index.html hardcodes rule, playbook, severity and category counts
in five places: the headline metric tiles, the hero terminal line, the
pipeline step, the rules-section title/intro, the severity-box grid, and the
"coverage by category" chart. README.md hardcodes the same rule and playbook
counts in its feature table and in two nodes of its Mermaid architecture
diagram. This script recomputes every count from scanner/rules/ and
playbooks/cli/ and rewrites both files in place, so neither can drift as
rules are added.

Every substitution is tracked. If a pattern matches zero times — because the
surrounding wording changed — the script fails loudly instead of silently
leaving the file unchanged and exiting 0.

Running the script against already-current files produces no changes, which
lets CI commit only on a real diff.
"""

import html
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = REPO_ROOT / "scanner" / "rules"
PLAYBOOKS_DIR = REPO_ROOT / "playbooks" / "cli"
LEARN_PAGE = REPO_ROOT / "docs" / "learn" / "index.html"
README_PATH = REPO_ROOT / "README.md"

# Rule modules are named az_<category>_<number>.py. Matching on that prefix is
# the same convention .github/workflows/ci.yml uses to discover rules, and it
# correctly excludes __init__.py and the shared _*_common.py helpers.
RULE_GLOB = "az_*.py"

SEVERITY_PATTERN = re.compile(r"^SEVERITY\s*=\s*[\"']([^\"']+)[\"']", re.MULTILINE)
CATEGORY_PATTERN = re.compile(r"^CATEGORY\s*=\s*[\"']([^\"']+)[\"']", re.MULTILINE)
RULE_ID_PATTERN = re.compile(r"^RULE_ID\s*=\s*[\"']([^\"']+)[\"']", re.MULTILINE)

# Counts that are not derived from the filesystem.
COMPLIANCE_FRAMEWORK_COUNT = 4  # CIS, NIST, ISO 27001, SOC 2
AI_SECURITY_SKILL_COUNT = 8


def count_rules() -> int:
    """Return the number of scanner rule modules that declare a RULE_ID."""
    if not RULES_DIR.is_dir():
        return 0
    return sum(1 for path in RULES_DIR.glob(RULE_GLOB) if RULE_ID_PATTERN.search(path.read_text(encoding="utf-8")))


def find_matching_playbooks() -> Tuple[int, List[str], List[str]]:
    """Return (playbook_count, missing_for_rules, orphan_playbook_files).

    Counting every *.sh file in playbooks/cli/ (the previous approach) also
    picks up shared helper scripts - e.g. review_enterprise_resilience.sh,
    which several fix_*.sh wrappers `exec` into rather than a playbook any
    single rule owns - silently inflating the count past rule_count and
    breaking the "every rule ships with a matching playbook" claim.

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


def collect_rule_stats() -> Tuple[Dict[str, int], Dict[str, int], List[str], List[str]]:
    """Parse every rule file once for its SEVERITY and CATEGORY.

    Returns (severity_counts, category_counts, files_missing_severity,
    files_missing_category). Severities and categories outside the values
    seen so far are still counted, keyed by whatever string the rule
    declares, so a new value is never silently dropped.

    Files with no parseable RULE_ID are skipped entirely, matching
    count_rules() - otherwise a non-rule file (excluded from rule_count)
    could still be counted into these totals, making the severity boxes
    disagree with the headline rule count.
    """
    severities: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    categories: Dict[str, int] = {}
    missing_severity: List[str] = []
    missing_category: List[str] = []

    if not RULES_DIR.is_dir():
        return severities, categories, missing_severity, missing_category

    for path in sorted(RULES_DIR.glob(RULE_GLOB)):
        content = path.read_text(encoding="utf-8")
        if not RULE_ID_PATTERN.search(content):
            continue

        sev_match = SEVERITY_PATTERN.search(content)
        if sev_match:
            severity = sev_match.group(1).strip().upper()
            severities[severity] = severities.get(severity, 0) + 1
        else:
            missing_severity.append(path.name)

        cat_match = CATEGORY_PATTERN.search(content)
        if cat_match:
            category = cat_match.group(1).strip()
            categories[category] = categories.get(category, 0) + 1
        else:
            missing_category.append(path.name)

    return severities, categories, missing_severity, missing_category


def render_category_rows(categories: Dict[str, int]) -> str:
    """Build the '<div class="bar-row">...' lines for the category chart.

    Rows are sorted by descending count (alphabetical tiebreak) so a newly
    added category appears automatically instead of requiring a code change.
    Bar width is each category's count as a percentage of the largest
    category, matching the original hand-authored chart's convention.
    """
    if not categories:
        return ""

    max_count = max(categories.values())
    rows = []
    for name, count in sorted(categories.items(), key=lambda item: (-item[1], item[0])):
        width = round(count / max_count * 100)
        rows.append(
            f'            <div class="bar-row"><span>{html.escape(name)}</span>'
            f'<div class="bar"><span style="width: {width}%;"></span></div>'
            f"<span>{count}</span></div>"
        )
    return "\n".join(rows)


def _metric(label: str) -> str:
    """Build the pattern for one headline metric tile on the Learn page."""
    return rf'(<div class="metric"><strong>)\d+(</strong><span>{re.escape(label)}</span></div>)'


def apply_replacements(content: str, replacements: Tuple[Tuple[str, str, int], ...]) -> Tuple[str, List[str]]:
    """Apply each (name, pattern, value) substitution, tracking zero-match failures.

    A pattern that matches zero times means the surrounding wording no longer
    matches what this script expects — that is reported as a failure rather
    than silently leaving the file unchanged.
    """
    failures: List[str] = []
    for name, pattern, value in replacements:
        content, count = re.subn(pattern, rf"\g<1>{value}\g<2>", content)
        if count == 0:
            failures.append(name)
    return content, failures


def render(
    content: str,
    rule_count: int,
    playbook_count: int,
    high_count: int,
    medium_count: int,
    low_count: int,
    category_rows: str,
) -> Tuple[str, List[str]]:
    """Return (updated_content, failed_pattern_names) for docs/learn/index.html."""
    intro = (
        r'(<p class="section-intro">\s*OpenShield currently has )\d+'
        r"( dynamic rules\. The strongest contributor work improves rule "
        r"accuracy, reduces false positives,)"
    )
    pipeline = (
        r'(<div class="pipeline-step"><strong>Rule Evaluation</strong><span>)'
        r"\d+( dynamic checks</span></div>)"
    )
    section_title = r'(<h2 class="section-title">)\d+( Azure security rules</h2>)'
    hero_terminal = r'(<span class="dim">loading rules:</span> <span class="cyan">)\d+( dynamic checks</span></p>)'
    severity_high = r'(<div class="severity-box high"><strong>)\d+(</strong><span>HIGH</span></div>)'
    severity_medium = r'(<div class="severity-box medium"><strong>)\d+(</strong><span>MEDIUM</span></div>)'
    severity_low = r'(<div class="severity-box low"><strong>)\d+(</strong><span>LOW</span></div>)'

    replacements: Tuple[Tuple[str, str, int], ...] = (
        ("headline metric: Azure scan rules", _metric("Azure scan rules"), rule_count),
        ("headline metric: CLI remediation playbooks", _metric("CLI remediation playbooks"), playbook_count),
        ("headline metric: Compliance frameworks", _metric("Compliance frameworks"), COMPLIANCE_FRAMEWORK_COUNT),
        ("headline metric: AI security skills", _metric("AI security skills"), AI_SECURITY_SKILL_COUNT),
        ("headline metric: High-severity checks", _metric("High-severity checks"), high_count),
        ("pipeline step: Rule Evaluation", pipeline, rule_count),
        ("rules section title", section_title, rule_count),
        ("rules section intro paragraph", intro, rule_count),
        ("hero terminal: dynamic checks line", hero_terminal, rule_count),
        ("severity box: HIGH", severity_high, high_count),
        ("severity box: MEDIUM", severity_medium, medium_count),
        ("severity box: LOW", severity_low, low_count),
    )

    content, failures = apply_replacements(content, replacements)

    category_block = r'(<div class="rule-chart" aria-label="Rule count by category">\n)(.*?)(\n {10}</div>)'
    content, count = re.subn(
        category_block,
        lambda m: m.group(1) + category_rows + m.group(3),
        content,
        flags=re.DOTALL,
    )
    if count == 0:
        failures.append("coverage-by-category chart")

    return content, failures


def render_readme(content: str, rule_count: int, playbook_count: int) -> Tuple[str, List[str]]:
    """Return (updated_content, failed_pattern_names) for README.md."""
    feature_row = (
        r"(\| \*\*Misconfiguration Scanner\*\* \| Runs )\d+"
        r"( Azure security rules across storage, network, identity, database, "
        r"compute, Key Vault, AKS, post-quantum cryptography, backup, serverless, "
        r"private endpoint, and supply chain posture \|)"
    )
    playbook_row = (
        r"(\| \*\*Remediation Playbooks\*\* \| Every rule ships with a matching "
        r"Azure CLI remediation script \()\d+( playbooks\) \|)"
    )
    mermaid_scanner = r'(C\["Scanner Engine\\n)\d+( Python rules"\])'
    mermaid_playbooks = r'(G\["Azure CLI Playbooks\\n)\d+( remediation scripts"\])'

    replacements: Tuple[Tuple[str, str, int], ...] = (
        ("feature table: Misconfiguration Scanner row", feature_row, rule_count),
        ("feature table: Remediation Playbooks row", playbook_row, playbook_count),
        ("Mermaid diagram: Scanner Engine node", mermaid_scanner, rule_count),
        ("Mermaid diagram: Azure CLI Playbooks node", mermaid_playbooks, playbook_count),
    )

    return apply_replacements(content, replacements)


def main() -> int:
    """Rewrite the Learn page and README statistics; return a process exit code."""
    for path in (LEARN_PAGE, README_PATH):
        if not path.is_file():
            print(f"Error: {path} not found", file=sys.stderr)
            return 1

    rule_count = count_rules()
    playbook_count, missing_playbooks, orphan_playbooks = find_matching_playbooks()

    if rule_count == 0 or playbook_count == 0:
        print(
            "Error: found no rules or no playbooks; refusing to write zeroes into the docs.",
            file=sys.stderr,
        )
        return 1

    if missing_playbooks:
        print(
            f"Error: {len(missing_playbooks)} rule(s) have no matching playbook file: {', '.join(missing_playbooks)}",
            file=sys.stderr,
        )
        return 1

    # Belt-and-suspenders: find_matching_playbooks() only counts playbooks
    # that resolve to a counted rule, so this should be unreachable once
    # missing_playbooks is empty. Failing loudly here catches a future bug
    # in that derivation rather than silently writing mismatched docs -
    # this is exactly the drift class (rules and playbooks disagreeing)
    # this script exists to catch.
    if rule_count != playbook_count:
        print(
            f"Error: rule/playbook count mismatch (rules: {rule_count}, playbooks: "
            f"{playbook_count}); refusing to write inconsistent docs.",
            file=sys.stderr,
        )
        return 1

    if orphan_playbooks:
        print(
            f"Warning: {len(orphan_playbooks)} playbook file(s) in playbooks/cli/ are not "
            f"any rule's matching playbook and are excluded from the playbook count "
            f"(expected for shared helpers other playbooks exec into): {', '.join(orphan_playbooks)}",
            file=sys.stderr,
        )

    severities, categories, missing_severity, missing_category = collect_rule_stats()

    if missing_severity:
        print(
            f"Warning: {len(missing_severity)} rule file(s) have no parseable SEVERITY "
            f"and are excluded from the severity counts: {', '.join(missing_severity)}",
            file=sys.stderr,
        )
    if missing_category:
        print(
            f"Warning: {len(missing_category)} rule file(s) have no parseable CATEGORY "
            f"and are excluded from the coverage-by-category chart: {', '.join(missing_category)}",
            file=sys.stderr,
        )

    chart_severities = {"HIGH", "MEDIUM", "LOW"}
    excluded_severities = {
        severity: count for severity, count in severities.items() if severity not in chart_severities and count
    }
    if excluded_severities:
        excluded_detail = ", ".join(f"{severity}: {count}" for severity, count in sorted(excluded_severities.items()))
        excluded_total = sum(excluded_severities.values())
        print(
            f"Warning: {excluded_total} rule(s) with severities outside the "
            f"HIGH/MEDIUM/LOW chart are excluded from the severity boxes: {excluded_detail}",
            file=sys.stderr,
        )

    category_rows = render_category_rows(categories)

    learn_original = LEARN_PAGE.read_text(encoding="utf-8")
    learn_updated, learn_failures = render(
        learn_original,
        rule_count,
        playbook_count,
        severities["HIGH"],
        severities["MEDIUM"],
        severities["LOW"],
        category_rows,
    )

    readme_original = README_PATH.read_text(encoding="utf-8")
    readme_updated, readme_failures = render_readme(readme_original, rule_count, playbook_count)

    failures = [f"docs/learn/index.html -> {name}" for name in learn_failures]
    failures += [f"README.md -> {name}" for name in readme_failures]

    if failures:
        print(
            "Error: the following patterns matched zero times. The surrounding wording "
            "has likely changed and this script needs updating to match:",
            file=sys.stderr,
        )
        for name in failures:
            print(f"  - {name}", file=sys.stderr)
        return 1

    changed: List[str] = []
    if learn_updated != learn_original:
        LEARN_PAGE.write_text(learn_updated, encoding="utf-8")
        changed.append(str(LEARN_PAGE.relative_to(REPO_ROOT)))
    if readme_updated != readme_original:
        README_PATH.write_text(readme_updated, encoding="utf-8")
        changed.append(str(README_PATH.relative_to(REPO_ROOT)))

    if not changed:
        print("Learn page and README statistics already current; nothing to do.")
        return 0

    print(
        f"Updated {', '.join(changed)} - rules: {rule_count}, playbooks: {playbook_count}, "
        f"severity HIGH: {severities['HIGH']}, MEDIUM: {severities['MEDIUM']}, LOW: {severities['LOW']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
