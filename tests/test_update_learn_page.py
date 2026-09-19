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
