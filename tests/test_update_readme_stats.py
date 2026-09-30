"""Focused tests for the README statistics script."""

import importlib.util
from pathlib import Path


_SCRIPT = Path(__file__).parents[1] / ".github" / "scripts" / "update_readme_stats.py"
_SPEC = importlib.util.spec_from_file_location("update_readme_stats", _SCRIPT)
assert _SPEC and _SPEC.loader
stats = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(stats)


def _readme(scanner_prose: str, playbook_prose: str, count: int = 5) -> str:
    return (
        f"| **Misconfiguration Scanner** | Runs {count}{scanner_prose} |\n"
        f"| **Remediation Playbooks** | {playbook_prose} ({count} playbooks) |\n"
        f'    C["Scanner Engine\\n{count} Python rules"]\n'
        f'    G["Azure CLI Playbooks\\n{count} remediation scripts"]\n'
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
    content, failures = stats.render_readme(reworded, 143, 143)
    assert failures == []
    assert "Runs 143 Azure security rules" in content
    assert "(143 playbooks)" in content
    assert 'C["Scanner Engine\\n143 Python rules"]' in content
    assert 'G["Azure CLI Playbooks\\n143 remediation scripts"]' in content


def test_render_readme_still_fails_when_a_row_disappears():
    missing = _readme(" Azure security rules across storage", "Every rule ships with a script").replace(
        "| **Remediation Playbooks** |", "| **Removed** |"
    )
    _, failures = stats.render_readme(missing, 143, 143)
    assert "feature table: Remediation Playbooks row" in failures


def _point_at(tmp_path, monkeypatch, readme_count: int) -> Path:
    rules = tmp_path / "scanner" / "rules"
    playbooks = tmp_path / "playbooks" / "cli"
    rules.mkdir(parents=True)
    playbooks.mkdir(parents=True)
    for n in (1, 2):
        (rules / f"az_net_00{n}.py").write_text(f'RULE_ID = "AZ-NET-00{n}"\n', encoding="utf-8")
        (playbooks / f"fix_az_net_00{n}.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    readme = tmp_path / "README.md"
    readme.write_text(_readme(" Azure security rules", "Every rule ships a script", readme_count), encoding="utf-8")
    monkeypatch.setattr(stats, "RULES_DIR", rules)
    monkeypatch.setattr(stats, "PLAYBOOKS_DIR", playbooks)
    monkeypatch.setattr(stats, "README_PATH", readme)
    return readme


def test_check_reports_stale_readme_without_writing(tmp_path, monkeypatch):
    readme = _point_at(tmp_path, monkeypatch, readme_count=1)
    before = readme.read_text(encoding="utf-8")
    assert stats.main(["--check"]) == stats.EXIT_STALE
    assert readme.read_text(encoding="utf-8") == before


def test_check_passes_when_readme_is_current(tmp_path, monkeypatch):
    _point_at(tmp_path, monkeypatch, readme_count=2)
    assert stats.main(["--check"]) == 0


def test_default_mode_rewrites_stale_counts(tmp_path, monkeypatch):
    readme = _point_at(tmp_path, monkeypatch, readme_count=1)
    assert stats.main([]) == 0
    assert "Runs 2 Azure security rules" in readme.read_text(encoding="utf-8")
    assert stats.main(["--check"]) == 0
