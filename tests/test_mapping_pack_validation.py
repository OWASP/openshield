"""Unit tests for .github/scripts/validate_mapping_pack.py against fixture
directories, so the mapping-pack semantics rules are exercised directly
rather than only implicitly via CI running against the real framework files.
"""

import importlib.util
import json
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / ".github" / "scripts" / "validate_mapping_pack.py"
_spec = importlib.util.spec_from_file_location("validate_mapping_pack", SCRIPT_PATH)
validate_mapping_pack = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(validate_mapping_pack)

validate_framework_dir = validate_mapping_pack.validate_framework_dir


def _control(**overrides):
    base = {
        "control_id": "1.1",
        "control_name": "Example control",
        "description": "Example description",
        "mapping_type": "direct",
        "evidence_type": "automated_configuration_scan",
        "primary_source": "Example Framework v1.0, control 1.1",
        "rationale": "This rule evaluates exactly the setting this control requires.",
        "owner": None,
        "review_status": "pending_review",
        "review_date": None,
    }
    base.update(overrides)
    return base


def _pack(controls, **overrides):
    base = {
        "framework": "Example Framework",
        "version": "1.0",
        "mapping_pack_version": "1.0.0",
        "mapping_pack_status": "current",
        "mapping_pack_source": "Test fixture",
        "mapping_pack_published": "2026-08-22",
        "controls": controls,
    }
    base.update(overrides)
    return base


def _write(tmp_path, name, pack):
    path = tmp_path / name
    with open(path, "w") as fh:
        json.dump(pack, fh)
    return path


def test_valid_pack_produces_no_failures(tmp_path):
    _write(tmp_path, "example.json", _pack({"AZ-EX-001": _control()}))
    assert validate_framework_dir(tmp_path) == []


def test_na_control_id_classified_direct_fails(tmp_path):
    """The exact bug this check exists to catch: a synthetic N/A-* control ID
    (this repository's own convention for 'no real framework control exists')
    still marked as direct technical evidence."""
    control = _control(
        control_id="N/A-EX-001",
        control_name="Not mapped in Example Framework v1.0",
        mapping_type="direct",
    )
    _write(tmp_path, "example.json", _pack({"AZ-EX-001": control}))
    failures = validate_framework_dir(tmp_path)
    assert any("must be 'not_applicable'" in f for f in failures)


def test_na_control_id_classified_not_applicable_passes(tmp_path):
    control = _control(
        control_id="N/A-EX-001",
        control_name="Not mapped in Example Framework v1.0",
        mapping_type="not_applicable",
        evidence_type="not_applicable",
    )
    _write(tmp_path, "example.json", _pack({"AZ-EX-001": control}))
    assert validate_framework_dir(tmp_path) == []


def test_prose_disclaimer_classified_direct_fails(tmp_path):
    """Even without an N/A- prefixed ID, text that explicitly disclaims a
    real mapping ('not directly mapped', etc.) cannot be paired with direct."""
    control = _control(
        control_id="9.9",
        description="This control is not directly mapped to any Example Framework requirement.",
        mapping_type="direct",
    )
    _write(tmp_path, "example.json", _pack({"AZ-EX-001": control}))
    failures = validate_framework_dir(tmp_path)
    assert any("must be 'not_applicable'" in f for f in failures)


def test_invalid_mapping_type_fails(tmp_path):
    _write(tmp_path, "example.json", _pack({"AZ-EX-001": _control(mapping_type="mostly_direct")}))
    failures = validate_framework_dir(tmp_path)
    assert any("mapping_type 'mostly_direct'" in f for f in failures)


def test_not_applicable_with_automated_scan_evidence_type_fails(tmp_path):
    control = _control(mapping_type="not_applicable", evidence_type="automated_configuration_scan")
    _write(tmp_path, "example.json", _pack({"AZ-EX-001": control}))
    failures = validate_framework_dir(tmp_path)
    assert any("cannot have evidence_type" in f for f in failures)


def test_reviewed_without_owner_or_date_fails(tmp_path):
    control = _control(review_status="reviewed", owner=None, review_date=None)
    _write(tmp_path, "example.json", _pack({"AZ-EX-001": control}))
    failures = validate_framework_dir(tmp_path)
    assert any("owner and/or review_date is missing" in f for f in failures)


def test_reviewed_with_owner_and_date_passes(tmp_path):
    control = _control(review_status="reviewed", owner="security-team", review_date="2026-08-22")
    _write(tmp_path, "example.json", _pack({"AZ-EX-001": control}))
    assert validate_framework_dir(tmp_path) == []


def test_reviewed_with_malformed_review_date_fails(tmp_path):
    """review_date must be a real ISO date, not just any non-empty string - a
    typo'd date must not silently pass CI the way mapping_pack_published's
    equivalent check already catches for the pack-level field."""
    control = _control(review_status="reviewed", owner="security-team", review_date="08/22/2026")
    _write(tmp_path, "example.json", _pack({"AZ-EX-001": control}))
    failures = validate_framework_dir(tmp_path)
    assert any("review_date '08/22/2026' is not a valid ISO date" in f for f in failures)


def test_missing_rationale_fails(tmp_path):
    control = _control(rationale="")
    _write(tmp_path, "example.json", _pack({"AZ-EX-001": control}))
    failures = validate_framework_dir(tmp_path)
    assert any("'rationale' must be a non-empty string" in f for f in failures)


def test_invalid_semantic_version_fails(tmp_path):
    _write(tmp_path, "example.json", _pack({"AZ-EX-001": _control()}, mapping_pack_version="v1.0"))
    failures = validate_framework_dir(tmp_path)
    assert any("not a valid semantic version" in f for f in failures)


def test_valid_semantic_version_passes(tmp_path):
    _write(tmp_path, "example.json", _pack({"AZ-EX-001": _control()}, mapping_pack_version="2.3.10"))
    assert validate_framework_dir(tmp_path) == []


def test_invalid_iso_date_fails(tmp_path):
    _write(tmp_path, "example.json", _pack({"AZ-EX-001": _control()}, mapping_pack_published="08/22/2026"))
    failures = validate_framework_dir(tmp_path)
    assert any("not a valid ISO date" in f for f in failures)


def test_invalid_pack_status_fails(tmp_path):
    _write(tmp_path, "example.json", _pack({"AZ-EX-001": _control()}, mapping_pack_status="draft"))
    failures = validate_framework_dir(tmp_path)
    assert any("mapping_pack_status 'draft'" in f for f in failures)


def test_legacy_pack_status_passes(tmp_path):
    _write(tmp_path, "example.json", _pack({"AZ-EX-001": _control()}, mapping_pack_status="legacy"))
    assert validate_framework_dir(tmp_path) == []


def test_missing_top_level_field_fails(tmp_path):
    pack = _pack({"AZ-EX-001": _control()})
    del pack["mapping_pack_source"]
    _write(tmp_path, "example.json", pack)
    failures = validate_framework_dir(tmp_path)
    assert any("missing or empty top-level 'mapping_pack_source'" in f for f in failures)


def test_malformed_json_is_reported_not_raised(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not valid json")
    failures = validate_framework_dir(tmp_path)
    assert any("could not parse" in f for f in failures)


def test_real_repository_framework_files_pass():
    """The actual shipped framework files must always satisfy this validator -
    this is the same check CI runs, exercised here so a regression is caught
    by the unit-test suite too, not only a full CI run."""
    real_dir = Path(__file__).resolve().parents[1] / "compliance" / "frameworks"
    assert validate_framework_dir(real_dir) == []
