"""Validation tests for the Sentinel JSON ingestion boundary."""

import json

import pytest

from api.validation import ValidationError
import sentinel.ingest as ingest
from sentinel.ingest import load_findings, normalise


def test_load_findings_rejects_non_json_path(tmp_path):
    path = tmp_path / "findings.txt"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValidationError, match="JSON file"):
        load_findings(path)


def test_load_findings_rejects_wrong_shape(tmp_path):
    path = tmp_path / "findings.json"
    path.write_text(json.dumps({"findings": "not-a-list"}), encoding="utf-8")
    with pytest.raises(ValidationError, match="findings list"):
        load_findings(path)


def test_normalise_rejects_non_object_and_invalid_severity():
    with pytest.raises(ValidationError, match="object"):
        normalise("finding", "scan-1")
    with pytest.raises(ValidationError, match="severity"):
        normalise({"severity": "urgent"}, "scan-1")


@pytest.mark.parametrize("finding", ({}, {"severity": None}, {"severity": ""}))
def test_normalise_rejects_missing_or_empty_severity(finding):
    with pytest.raises(ValidationError, match="severity is required"):
        normalise(finding, "scan-1")


def test_normalise_accepts_bounded_finding():
    record = normalise(
        {"id": 1, "severity": "HIGH", "rule_id": "AZ-NET-001", "compliance": {"cis": "1.1"}},
        "scan-1",
    )
    assert record["Severity"] == "High"
    assert record["RuleId"] == "AZ-NET-001"


def test_normalise_canonicalizes_informational_alias():
    record = normalise({"severity": "INFORMATIONAL"}, "scan-1")
    assert record["Severity"] == "Info"
    assert record["SeverityScore"] == 0


def test_main_handles_invalid_config_without_traceback(monkeypatch, capsys):
    monkeypatch.setattr(ingest, "WORKSPACE_ID", "")
    monkeypatch.setattr(ingest.sys, "argv", ["ingest.py"])

    assert ingest.main() == 2
    captured = capsys.readouterr()
    assert "Invalid Sentinel configuration or findings input" in captured.err
    assert "Traceback" not in captured.err


def test_main_rejects_entire_batch_before_send_when_one_record_is_invalid(monkeypatch, tmp_path):
    path = tmp_path / "findings.json"
    path.write_text(json.dumps([{"severity": "HIGH"}, {"severity": "urgent"}]), encoding="utf-8")
    monkeypatch.setattr(ingest, "WORKSPACE_ID", "00000000-0000-0000-0000-000000000001")
    monkeypatch.setattr(ingest, "SHARED_KEY", "c2VjcmV0")
    monkeypatch.setattr(ingest.sys, "argv", ["ingest.py", str(path), "scan-1"])
    called = []
    monkeypatch.setattr(ingest, "send", called.append)

    assert ingest.main() == 2
    assert called == []
