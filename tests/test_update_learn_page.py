"""Focused tests for the generated Learn-route statistics contract."""

import importlib.util
from pathlib import Path


_SCRIPT = Path(__file__).parents[1] / ".github" / "scripts" / "update_learn_page.py"
_SPEC = importlib.util.spec_from_file_location("update_learn_page", _SCRIPT)
assert _SPEC and _SPEC.loader
learn = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(learn)


def _route_with_severity_boxes() -> str:
    return (
        """<div class="metrics" aria-label="OpenShield project metrics">
<div class="metric"><strong>1</strong><span>Azure scan rules</span></div>
<div class="metric"><strong>1</strong><span>CLI remediation playbooks</span></div>
<div class="metric"><strong>1</strong><span>Compliance frameworks</span></div>
<div class="metric"><strong>1</strong><span>AI security skills</span></div>
<div class="metric"><strong>1</strong><span>High-severity checks</span></div>
</div>
<p><span class="dim">loading rules:</span> <span class="cyan">1 dynamic checks</span></p>
<div class="pipeline-step"><strong>Rule Evaluation</strong><span>1 dynamic checks</span></div>
<h2 class="section-title">1 Azure security rules</h2>
<p class="section-intro">OpenShield currently has 1 dynamic rules. """
        """The strongest contributor work improves rule accuracy, reduces false positives,</p>
<div class="rule-chart" aria-label="Rule count by category">
  <div class="bar-row"><span>Old</span></div>
</div>
<div class="severity-box critical"><strong>0</strong><span>CRITICAL</span></div>
<div class="severity-box high"><strong>0</strong><span>HIGH</span></div>
<div class="severity-box medium"><strong>0</strong><span>MEDIUM</span></div>
<div class="severity-box low"><strong>0</strong><span>LOW</span></div>"""
    )


def test_render_updates_critical_box_and_requires_it():
    content, failures = learn.render(_route_with_severity_boxes(), 10, 10, 2, 5, 2, 1, "<div>category</div>")
    assert failures == []
    assert '<div class="severity-box critical"><strong>2</strong><span>CRITICAL</span></div>' in content

    _, failures = learn.render(
        _route_with_severity_boxes().replace("severity-box critical", "severity-box removed"),
        10,
        10,
        2,
        5,
        2,
        1,
        "<div>category</div>",
    )
    assert "severity box: CRITICAL" in failures


def test_validate_statistics_rejects_partial_severity_or_category_totals():
    severities = {"CRITICAL": 2, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    assert learn.validate_statistics(10, severities, {"Network": 6, "Identity": 4}) is None
    assert learn.validate_statistics(10, severities, {"Network": 9}) is not None
    assert learn.validate_statistics(10, {**severities, "INFO": 1}, {"Network": 6, "Identity": 4}) is not None


def _readme(scanner_prose: str, playbook_prose: str) -> str:
    return (
        f"| **Misconfiguration Scanner** | Runs 5{scanner_prose} |\n"
        f"| **Remediation Playbooks** | {playbook_prose} (5 playbooks) |\n"
        '    C["Scanner Engine\\n5 Python rules"]\n'
        '    G["Azure CLI Playbooks\\n5 remediation scripts"]\n'
    )


def test_render_readme_survives_reworded_feature_rows():
    """The counts, not the surrounding prose, are what this script owns.

    Both rows are edited independently of the counts (the category list grows,
    the scripts get re-described). Pinning the whole sentence made the script
    fail on an unrelated reword while the counts silently went stale, which is
    exactly the drift it exists to prevent.
    """
    reworded = _readme(
        " Azure security rules across storage, network, and a category added later",
        "Every documented rule ships with a matching review-gated remediation script",
    )
    content, failures = learn.render_readme(reworded, 143, 143)
    assert failures == []
    assert "Runs 143 Azure security rules" in content
    assert "(143 playbooks)" in content
    assert 'C["Scanner Engine\\n143 Python rules"]' in content
    assert 'G["Azure CLI Playbooks\\n143 remediation scripts"]' in content


def test_render_readme_still_fails_when_a_row_disappears():
    missing = _readme(" Azure security rules across storage", "Every rule ships with a script").replace(
        "| **Remediation Playbooks** |", "| **Removed** |"
    )
    _, failures = learn.render_readme(missing, 143, 143)
    assert "feature table: Remediation Playbooks row" in failures
