"""Tests for the compliance mapping-pack scoring in DatabaseManager.get_compliance_score()
and the mapping-pack snapshot persisted by save_scan() (issue #302)."""

import json
from unittest.mock import MagicMock, patch

import api.models.finding as finding_module
import api.routes.compliance as compliance_route


def _db(dsn="postgresql://mock/mock"):
    db = finding_module.DatabaseManager.__new__(finding_module.DatabaseManager)
    db.dsn = dsn
    db.conn = None
    return db


def _mock_cursor(fetchone_return=None, fetchall_return=None):
    cur = MagicMock()
    cur.__enter__ = lambda s: s
    cur.__exit__ = MagicMock(return_value=False)
    cur.fetchone.return_value = fetchone_return
    cur.fetchall.return_value = fetchall_return or []
    return cur


def _write_framework(tmp_path, filename, controls, **pack_overrides):
    data = {
        "framework": "Test Framework",
        "version": "1.0",
        "published": "2026-01",
        "mapping_pack_version": "1.0.0",
        "mapping_pack_status": "current",
        "mapping_pack_source": "test fixture",
        "mapping_pack_published": "2026-08-22",
        "controls": controls,
    }
    data.update(pack_overrides)
    path = tmp_path / filename
    with open(path, "w") as fh:
        json.dump(data, fh)
    return path


def _control(control_id, mapping_type="direct"):
    return {
        "control_id": control_id,
        "control_name": f"Control {control_id}",
        "description": "test",
        "mapping_type": mapping_type,
        "evidence_type": "not_applicable"
        if mapping_type in ("not_applicable", "organizational")
        else "automated_configuration_scan",
        "primary_source": "test source",
        "rationale": "test rationale",
        "owner": None,
        "review_status": "pending_review",
        "review_date": None,
    }


# ── No completed scan: must never report a passing score from absent data ──


def test_no_completed_scan_returns_no_scan_data_not_a_pass():
    db = _db()
    conn = MagicMock()
    conn.cursor.return_value = _mock_cursor(fetchone_return=None)
    with (
        patch.object(db, "_get_conn", return_value=conn),
        patch.object(finding_module, "FRAMEWORKS_DIR", finding_module.FRAMEWORKS_DIR),
    ):
        result = db.get_compliance_score("cis")

    assert result["status"] == "NO_SCAN_DATA"
    assert result["score_percent"] is None
    # None, not 0 - a literal 0 would read as "this pack has zero in-scope
    # controls" (the distinct NO_IN_SCOPE_CONTROLS case), when nothing has
    # actually been evaluated yet.
    assert result["passed"] is None
    assert result["failed"] is None
    assert result["in_scope_controls"] is None
    assert result["excluded_controls"] is None
    assert "error" not in result  # route must return 200, not 500, for this normal state
    assert result["controls"] == []
    assert "evaluation_basis" in result


# ── Unknown framework / missing file ────────────────────────────────────────


def test_unknown_framework_returns_error():
    db = _db()
    result = db.get_compliance_score("not-a-real-framework")
    assert "error" in result


# ── PASS / FAIL / exclusion semantics, using a synthetic framework file ────


def _patched_db_with_framework(tmp_path, controls, scan_row, finding_rows):
    db = _db()
    conn = MagicMock()
    cur = _mock_cursor(fetchone_return=scan_row, fetchall_return=finding_rows)
    conn.cursor.return_value = cur

    framework_file = "test_fw.json"
    _write_framework(tmp_path, framework_file, controls)

    return db, conn, framework_file


def test_direct_control_with_no_findings_is_pass(tmp_path, monkeypatch):
    controls = {"AZ-TEST-001": _control("1.1", "direct")}
    scan_row = {"scan_id": "scan-1", "compliance_mapping_snapshot": None}
    db, conn, framework_file = _patched_db_with_framework(tmp_path, controls, scan_row, [])

    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    monkeypatch.setitem(finding_module.FRAMEWORK_FILE_MAP, "testfw", framework_file)

    with patch.object(db, "_get_conn", return_value=conn):
        result = db.get_compliance_score("testfw")

    assert result["controls"][0]["status"] == "PASS"
    assert result["passed"] == 1
    assert result["failed"] == 0
    assert result["score_percent"] == 100


def test_control_with_finding_is_fail(tmp_path, monkeypatch):
    controls = {"AZ-TEST-001": _control("1.1", "direct")}
    scan_row = {"scan_id": "scan-1", "compliance_mapping_snapshot": None}
    finding_rows = [("AZ-TEST-001", "HIGH", "Storage", 1)]
    db, conn, framework_file = _patched_db_with_framework(tmp_path, controls, scan_row, finding_rows)

    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    monkeypatch.setitem(finding_module.FRAMEWORK_FILE_MAP, "testfw", framework_file)

    with patch.object(db, "_get_conn", return_value=conn):
        result = db.get_compliance_score("testfw")

    assert result["controls"][0]["status"] == "FAIL"
    assert result["passed"] == 0
    assert result["failed"] == 1
    assert result["score_percent"] == 0


def test_not_applicable_and_organizational_excluded_from_denominator(tmp_path, monkeypatch):
    controls = {
        "AZ-TEST-001": _control("1.1", "direct"),  # PASS
        "AZ-TEST-002": _control("1.2", "direct"),  # FAIL
        "AZ-TEST-003": _control("1.3", "not_applicable"),
        "AZ-TEST-004": _control("1.4", "organizational"),
    }
    scan_row = {"scan_id": "scan-1", "compliance_mapping_snapshot": None}
    finding_rows = [("AZ-TEST-002", "HIGH", "Storage", 1)]
    db, conn, framework_file = _patched_db_with_framework(tmp_path, controls, scan_row, finding_rows)

    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    monkeypatch.setitem(finding_module.FRAMEWORK_FILE_MAP, "testfw", framework_file)

    with patch.object(db, "_get_conn", return_value=conn):
        result = db.get_compliance_score("testfw")

    statuses = {c["rule_id"]: c["status"] for c in result["controls"]}
    assert statuses["AZ-TEST-001"] == "PASS"
    assert statuses["AZ-TEST-002"] == "FAIL"
    assert statuses["AZ-TEST-003"] == "NOT_APPLICABLE"
    assert statuses["AZ-TEST-004"] == "ORGANIZATIONAL"

    assert result["total_controls"] == 4
    assert result["excluded_controls"] == 2
    assert result["in_scope_controls"] == 2
    assert result["passed"] == 1
    assert result["failed"] == 1
    # Score is 1/2, not 1/4 — excluded controls must not dilute the denominator.
    assert result["score_percent"] == 50


def test_rule_that_did_not_complete_is_not_evaluated_not_pass(tmp_path, monkeypatch):
    """A rule the scan engine recorded as failed (raised, or returned
    malformed data - scanner/engine.py's failed_rule_ids) must not be read
    as a PASS just because it produced no findings. It's excluded from the
    denominator as NOT_EVALUATED instead, the same way not_applicable/
    organizational controls are, but for a different reason: this is
    missing evidence, not a control the mapping pack says a scan can't
    establish (issue #302 item 4)."""
    controls = {
        "AZ-TEST-001": _control("1.1", "direct"),  # ran clean -> PASS
        "AZ-TEST-002": _control("1.2", "direct"),  # ran, found a finding -> FAIL
        "AZ-TEST-003": _control("1.3", "direct"),  # never completed -> NOT_EVALUATED
    }
    scan_row = {
        "scan_id": "scan-1",
        "compliance_mapping_snapshot": {"_scan_rule_outcomes": {"failed_rule_ids": ["AZ-TEST-003"]}},
    }
    finding_rows = [("AZ-TEST-002", "HIGH", "Storage", 1)]
    db, conn, framework_file = _patched_db_with_framework(tmp_path, controls, scan_row, finding_rows)

    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    monkeypatch.setitem(finding_module.FRAMEWORK_FILE_MAP, "testfw", framework_file)

    with patch.object(db, "_get_conn", return_value=conn):
        result = db.get_compliance_score("testfw")

    statuses = {c["rule_id"]: c["status"] for c in result["controls"]}
    assert statuses["AZ-TEST-001"] == "PASS"
    assert statuses["AZ-TEST-002"] == "FAIL"
    assert statuses["AZ-TEST-003"] == "NOT_EVALUATED"

    assert result["total_controls"] == 3
    # AZ-TEST-003 is excluded from the denominator like not_applicable/
    # organizational controls, so in_scope is 2 (AZ-TEST-001, AZ-TEST-002).
    assert result["excluded_controls"] == 1
    assert result["in_scope_controls"] == 2
    assert result["passed"] == 1
    assert result["failed"] == 1
    assert result["score_percent"] == 50


def test_failed_rule_ids_from_an_older_scan_do_not_leak_into_a_later_ones_scoring(tmp_path, monkeypatch):
    """_scan_rule_outcomes is read from the latest scan's own snapshot only -
    a rule that failed on a previous scan but completed cleanly on the
    latest one must score PASS, not get stuck as NOT_EVALUATED forever."""
    controls = {"AZ-TEST-001": _control("1.1", "direct")}
    # The latest scan's snapshot has no _scan_rule_outcomes at all (it
    # completed with no rule failures), even though an earlier scan might
    # have recorded AZ-TEST-001 as failed.
    scan_row = {"scan_id": "scan-2", "compliance_mapping_snapshot": {}}
    db, conn, framework_file = _patched_db_with_framework(tmp_path, controls, scan_row, [])

    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    monkeypatch.setitem(finding_module.FRAMEWORK_FILE_MAP, "testfw", framework_file)

    with patch.object(db, "_get_conn", return_value=conn):
        result = db.get_compliance_score("testfw")

    assert result["controls"][0]["status"] == "PASS"


def test_ok_status_and_score_present_when_controls_are_in_scope(tmp_path, monkeypatch):
    """A genuinely evaluated result must be explicitly distinguishable from
    NO_SCAN_DATA/NO_IN_SCOPE_CONTROLS by status, not just by score_percent
    happening to be non-null."""
    controls = {"AZ-TEST-001": _control("1.1", "direct")}
    scan_row = {"scan_id": "scan-1", "compliance_mapping_snapshot": None}
    db, conn, framework_file = _patched_db_with_framework(tmp_path, controls, scan_row, [])

    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    monkeypatch.setitem(finding_module.FRAMEWORK_FILE_MAP, "testfw", framework_file)

    with patch.object(db, "_get_conn", return_value=conn):
        result = db.get_compliance_score("testfw")

    assert result["status"] == "OK"
    assert result["score_percent"] == 100


def test_no_in_scope_controls_status_when_everything_is_excluded(tmp_path, monkeypatch):
    """A scan exists and every mapped control resolved, but all of them are
    not_applicable/organizational - this must be distinguishable from both
    NO_SCAN_DATA (no evidence exists at all) and a real evaluated score, not
    collapsed into the same null score_percent as either."""
    controls = {
        "AZ-TEST-001": _control("1.1", "not_applicable"),
        "AZ-TEST-002": _control("1.2", "organizational"),
    }
    scan_row = {"scan_id": "scan-1", "compliance_mapping_snapshot": None}
    db, conn, framework_file = _patched_db_with_framework(tmp_path, controls, scan_row, [])

    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    monkeypatch.setitem(finding_module.FRAMEWORK_FILE_MAP, "testfw", framework_file)

    with patch.object(db, "_get_conn", return_value=conn):
        result = db.get_compliance_score("testfw")

    assert result["status"] == "NO_IN_SCOPE_CONTROLS"
    assert result["score_percent"] is None
    assert result["in_scope_controls"] == 0
    assert result["total_controls"] == 2


def test_mapping_pack_snapshot_preferred_over_live_file(tmp_path, monkeypatch):
    """A full historical snapshot (controls + hash, not just metadata) wins
    over whatever is on disk now."""
    controls = {"AZ-TEST-001": _control("1.1", "direct")}
    historical_snapshot = {
        "testfw": {
            "framework": "Test Framework (historical)",
            "version": "0.9",
            "mapping_pack_version": "0.1.0",
            "mapping_pack_status": "legacy",
            "mapping_pack_source": "historical fixture",
            "mapping_pack_published": "2025-01-01",
            "controls": controls,
            finding_module._CONTENT_HASH_KEY: finding_module._compute_mapping_pack_content_hash(controls),
        }
    }
    scan_row = {"scan_id": "scan-1", "compliance_mapping_snapshot": historical_snapshot}
    db, conn, framework_file = _patched_db_with_framework(tmp_path, controls, scan_row, [])

    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    monkeypatch.setitem(finding_module.FRAMEWORK_FILE_MAP, "testfw", framework_file)

    with patch.object(db, "_get_conn", return_value=conn):
        result = db.get_compliance_score("testfw")

    # Report shows what was true when the scan ran, not the current file on disk.
    assert result["mapping_pack_version"] == "0.1.0"
    assert result["mapping_pack_status"] == "legacy"
    assert result["framework"] == "Test Framework (historical)"
    assert result["mapping_provenance"] == "snapshot"


def test_legacy_metadata_only_snapshot_is_not_labelled_snapshot(tmp_path, monkeypatch):
    """A snapshot saved before the full-controls capture existed (pack
    metadata only, no "controls" key) cannot reproduce the historical
    mapping - denominator/classification still has to come from the live
    file, so it must be labelled a live fallback, not "snapshot". Claiming
    "snapshot" here would be exactly the bug flagged in issue #302 item 3:
    presenting a live-data read as if it were historically accurate."""
    controls = {"AZ-TEST-001": _control("1.1", "direct")}
    historical_snapshot = {
        "testfw": {
            "framework": "Test Framework (historical)",
            "version": "0.9",
            "mapping_pack_version": "0.1.0",
            "mapping_pack_status": "legacy",
            "mapping_pack_source": "historical fixture",
            "mapping_pack_published": "2025-01-01",
        }
    }
    scan_row = {"scan_id": "scan-1", "compliance_mapping_snapshot": historical_snapshot}
    db, conn, framework_file = _patched_db_with_framework(tmp_path, controls, scan_row, [])

    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    monkeypatch.setitem(finding_module.FRAMEWORK_FILE_MAP, "testfw", framework_file)

    with patch.object(db, "_get_conn", return_value=conn):
        result = db.get_compliance_score("testfw")

    assert result["mapping_pack_version"] == "0.1.0"  # metadata still honored
    assert result["mapping_provenance"] == "live_fallback_legacy_snapshot"


def test_snapshot_hash_mismatch_is_flagged_not_silently_trusted(tmp_path, monkeypatch):
    """If a stored snapshot's controls no longer match its own recorded
    hash (corruption, partial write), that must be surfaced, not silently
    presented as a clean, verified "snapshot"."""
    controls = {"AZ-TEST-001": _control("1.1", "direct")}
    historical_snapshot = {
        "testfw": {
            "framework": "Test Framework",
            "version": "1.0",
            "mapping_pack_version": "1.0.0",
            "mapping_pack_status": "current",
            "mapping_pack_source": "historical fixture",
            "mapping_pack_published": "2025-01-01",
            "controls": controls,
            finding_module._CONTENT_HASH_KEY: "0" * 64,  # deliberately wrong
        }
    }
    scan_row = {"scan_id": "scan-1", "compliance_mapping_snapshot": historical_snapshot}
    db, conn, framework_file = _patched_db_with_framework(tmp_path, controls, scan_row, [])

    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    monkeypatch.setitem(finding_module.FRAMEWORK_FILE_MAP, "testfw", framework_file)

    with patch.object(db, "_get_conn", return_value=conn):
        result = db.get_compliance_score("testfw")

    assert result["mapping_provenance"] == "snapshot_hash_mismatch"
    # Still the best available historical data, so still used rather than
    # silently substituting the live file.
    assert result["controls"][0]["rule_id"] == "AZ-TEST-001"


def test_snapshot_missing_hash_is_not_labelled_plain_snapshot(tmp_path, monkeypatch):
    """A full snapshot (has "controls") saved before the content-hash field
    existed was never integrity-checked - it must not be labelled plain
    "snapshot", which would imply a verification that never happened."""
    controls = {"AZ-TEST-001": _control("1.1", "direct")}
    historical_snapshot = {
        "testfw": {
            "framework": "Test Framework",
            "version": "1.0",
            "mapping_pack_version": "1.0.0",
            "mapping_pack_status": "current",
            "mapping_pack_source": "historical fixture",
            "mapping_pack_published": "2025-01-01",
            "controls": controls,
            # No _CONTENT_HASH_KEY entry at all.
        }
    }
    scan_row = {"scan_id": "scan-1", "compliance_mapping_snapshot": historical_snapshot}
    db, conn, framework_file = _patched_db_with_framework(tmp_path, controls, scan_row, [])

    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    monkeypatch.setitem(finding_module.FRAMEWORK_FILE_MAP, "testfw", framework_file)

    with patch.object(db, "_get_conn", return_value=conn):
        result = db.get_compliance_score("testfw")

    assert result["mapping_provenance"] == "snapshot_no_hash"
    # Still the best available historical data, so still used.
    assert result["controls"][0]["rule_id"] == "AZ-TEST-001"


def test_mapping_update_after_scan_does_not_change_that_scans_reported_mapping(tmp_path, monkeypatch):
    """The exact acceptance test item 3 asked for: save a scan under a v1
    mapping pack, change the live mapping to v2, then query that same scan
    again and prove its controls, classification, denominator, hash, and
    metadata all remain v1 - not silently re-evaluated under v2."""
    v1_controls = {"AZ-TEST-001": _control("1.1", "direct")}
    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    framework_file = "test_fw.json"
    _write_framework(tmp_path, framework_file, v1_controls, mapping_pack_version="1.0.0")
    monkeypatch.setitem(finding_module.FRAMEWORK_FILE_MAP, "testfw", framework_file)

    # Simulate what save_scan() captured at v1 scan time.
    v1_snapshot = finding_module._build_compliance_mapping_snapshot()
    v1_hash = v1_snapshot["testfw"][finding_module._CONTENT_HASH_KEY]

    # The mapping pack is revised: AZ-TEST-001 becomes not_applicable and a
    # new control is added. This must never retroactively change how the v1
    # scan is reported.
    v2_controls = {
        "AZ-TEST-001": _control("1.1", "not_applicable"),
        "AZ-TEST-002": _control("1.2", "direct"),
    }
    _write_framework(tmp_path, framework_file, v2_controls, mapping_pack_version="2.0.0")

    scan_row = {"scan_id": "scan-1", "compliance_mapping_snapshot": v1_snapshot}
    db, conn, _ = _patched_db_with_framework(tmp_path, v2_controls, scan_row, [])

    with patch.object(db, "_get_conn", return_value=conn):
        result = db.get_compliance_score("testfw")

    assert result["mapping_provenance"] == "snapshot"
    assert result["mapping_pack_version"] == "1.0.0"
    assert result[finding_module._CONTENT_HASH_KEY] == v1_hash
    assert list(result["controls"][0].keys())  # sanity: shape unchanged
    assert len(result["controls"]) == 1  # v1 had one control, not v2's two
    assert result["controls"][0]["rule_id"] == "AZ-TEST-001"
    assert result["controls"][0]["mapping_type"] == "direct"  # still v1's classification
    assert result["controls"][0]["status"] == "PASS"
    assert result["total_controls"] == 1
    assert result["in_scope_controls"] == 1


def test_mapping_provenance_flags_capture_failure_instead_of_silently_using_live_data(tmp_path, monkeypatch):
    """When this exact scan's snapshot attempt failed for this framework
    (recorded under _capture_errors at save time), falling back to the live
    file on disk is the only option, but the response must say so explicitly
    rather than presenting live data as if it were historically accurate."""
    controls = {"AZ-TEST-001": _control("1.1", "direct")}
    scan_row = {
        "scan_id": "scan-1",
        "compliance_mapping_snapshot": {"_capture_errors": {"testfw": "OSError: disk read failed"}},
    }
    db, conn, framework_file = _patched_db_with_framework(tmp_path, controls, scan_row, [])

    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    monkeypatch.setitem(finding_module.FRAMEWORK_FILE_MAP, "testfw", framework_file)

    with patch.object(db, "_get_conn", return_value=conn):
        result = db.get_compliance_score("testfw")

    assert result["mapping_provenance"] == "live_fallback_capture_failed"


def test_mapping_provenance_is_benign_fallback_when_scan_predates_snapshot_feature(tmp_path, monkeypatch):
    """An old scan saved before the snapshot feature existed (or before this
    framework was added) has neither a snapshot entry nor a recorded capture
    error for it - a real, benign fallback, distinct from a genuine failure."""
    controls = {"AZ-TEST-001": _control("1.1", "direct")}
    scan_row = {"scan_id": "scan-1", "compliance_mapping_snapshot": None}
    db, conn, framework_file = _patched_db_with_framework(tmp_path, controls, scan_row, [])

    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    monkeypatch.setitem(finding_module.FRAMEWORK_FILE_MAP, "testfw", framework_file)

    with patch.object(db, "_get_conn", return_value=conn):
        result = db.get_compliance_score("testfw")

    assert result["mapping_provenance"] == "live_fallback_no_snapshot"


# ── compliance_mapping_snapshot construction for save_scan() ───────────────


def test_build_compliance_mapping_snapshot_reads_all_frameworks(tmp_path, monkeypatch):
    for key, filename in finding_module.FRAMEWORK_FILE_MAP.items():
        _write_framework(tmp_path, filename, {})

    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    snapshot = finding_module._build_compliance_mapping_snapshot()

    assert set(snapshot.keys()) == set(finding_module.FRAMEWORK_FILE_MAP.keys())
    for entry in snapshot.values():
        assert entry["mapping_pack_version"] == "1.0.0"
        assert entry["mapping_pack_status"] == "current"


def test_build_compliance_mapping_snapshot_records_missing_file_not_silently(tmp_path, monkeypatch):
    """A missing framework file must never be silently omitted — it's
    recorded under "_capture_errors" so a later consumer of this exact
    snapshot can tell "never captured" apart from "nothing went wrong"."""
    # No framework files written at all — every FRAMEWORKS_DIR / filename lookup misses.
    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    snapshot = finding_module._build_compliance_mapping_snapshot()
    assert set(snapshot.keys()) == {"_capture_errors"}
    assert set(snapshot["_capture_errors"].keys()) == set(finding_module.FRAMEWORK_FILE_MAP.keys())
    assert all("FileNotFoundError" in msg for msg in snapshot["_capture_errors"].values())


def test_build_compliance_mapping_snapshot_records_malformed_file_not_silently(tmp_path, monkeypatch):
    for key, filename in finding_module.FRAMEWORK_FILE_MAP.items():
        (tmp_path / filename).write_text("{not valid json")
    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)

    snapshot = finding_module._build_compliance_mapping_snapshot()

    assert set(snapshot.keys()) == {"_capture_errors"}
    assert all("JSONDecodeError" in msg for msg in snapshot["_capture_errors"].values())


def test_build_compliance_mapping_snapshot_partial_failure_keeps_successful_frameworks(tmp_path, monkeypatch):
    """One framework failing to capture must not discard frameworks that
    captured successfully."""
    good_filename = next(iter(finding_module.FRAMEWORK_FILE_MAP.values()))
    _write_framework(tmp_path, good_filename, {})
    # Every other framework's file is left unwritten (missing).
    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)

    snapshot = finding_module._build_compliance_mapping_snapshot()

    good_key = next(k for k, v in finding_module.FRAMEWORK_FILE_MAP.items() if v == good_filename)
    assert good_key in snapshot
    assert snapshot[good_key]["mapping_pack_version"] == "1.0.0"
    assert "_capture_errors" in snapshot
    assert good_key not in snapshot["_capture_errors"]
    assert len(snapshot["_capture_errors"]) == len(finding_module.FRAMEWORK_FILE_MAP) - 1


def test_save_scan_persists_compliance_mapping_snapshot(tmp_path, monkeypatch):
    for key, filename in finding_module.FRAMEWORK_FILE_MAP.items():
        _write_framework(tmp_path, filename, {})
    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)

    db = _db()
    conn = MagicMock()
    conn.cursor.return_value = _mock_cursor()
    with patch.object(db, "_get_conn", return_value=conn):
        db.save_scan(
            {
                "scan_id": "scan-1",
                "subscription_id": "sub-1",
                "started_at": "2026-08-22T00:00:00Z",
                "completed_at": "2026-08-22T00:05:00Z",
                "total_findings": 0,
                "findings": [],
            }
        )

    executed_sql, params = conn.cursor.return_value.execute.call_args_list[0][0]
    assert "compliance_mapping_snapshot" in executed_sql
    snapshot_param = params[-1]
    snapshot = json.loads(snapshot_param)
    assert set(snapshot.keys()) == set(finding_module.FRAMEWORK_FILE_MAP.keys())


def test_save_scan_records_failed_rule_ids_into_snapshot(tmp_path, monkeypatch):
    """scanner/engine.py's failed_rule_ids must reach the persisted snapshot
    under _scan_rule_outcomes, so get_compliance_score() can later exclude
    those rules as NOT_EVALUATED instead of reading them as PASS."""
    for key, filename in finding_module.FRAMEWORK_FILE_MAP.items():
        _write_framework(tmp_path, filename, {})
    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)

    db = _db()
    conn = MagicMock()
    conn.cursor.return_value = _mock_cursor()
    with patch.object(db, "_get_conn", return_value=conn):
        db.save_scan(
            {
                "scan_id": "scan-1",
                "subscription_id": "sub-1",
                "started_at": "2026-08-22T00:00:00Z",
                "completed_at": "2026-08-22T00:05:00Z",
                "total_findings": 0,
                "findings": [],
                # Duplicates and unsorted input must not leak through verbatim.
                "failed_rule_ids": ["AZ-TEST-002", "AZ-TEST-001", "AZ-TEST-002"],
            }
        )

    executed_sql, params = conn.cursor.return_value.execute.call_args_list[0][0]
    snapshot = json.loads(params[-1])
    assert snapshot["_scan_rule_outcomes"] == {"failed_rule_ids": ["AZ-TEST-001", "AZ-TEST-002"]}


def test_save_scan_omits_scan_rule_outcomes_when_nothing_failed(tmp_path, monkeypatch):
    """A clean scan must not carry an empty _scan_rule_outcomes key - its
    absence is exactly what lets a later get_compliance_score() call treat
    every rule's silence as eligible for PASS."""
    for key, filename in finding_module.FRAMEWORK_FILE_MAP.items():
        _write_framework(tmp_path, filename, {})
    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)

    db = _db()
    conn = MagicMock()
    conn.cursor.return_value = _mock_cursor()
    with patch.object(db, "_get_conn", return_value=conn):
        db.save_scan(
            {
                "scan_id": "scan-1",
                "subscription_id": "sub-1",
                "started_at": "2026-08-22T00:00:00Z",
                "completed_at": "2026-08-22T00:05:00Z",
                "total_findings": 0,
                "findings": [],
                "failed_rule_ids": [],
            }
        )

    executed_sql, params = conn.cursor.return_value.execute.call_args_list[0][0]
    snapshot = json.loads(params[-1])
    assert "_scan_rule_outcomes" not in snapshot


def test_save_scan_upsert_refreshes_scan_rule_outcomes_on_every_write(tmp_path, monkeypatch):
    """The upsert must not let COALESCE freeze _scan_rule_outcomes along with
    the rest of the snapshot on a replay - framework provenance stays
    immutable, but per-attempt outcomes have to be re-merged from whichever
    attempt is actually being written, every time."""
    for key, filename in finding_module.FRAMEWORK_FILE_MAP.items():
        _write_framework(tmp_path, filename, {})
    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)

    db = _db()
    conn = MagicMock()
    conn.cursor.return_value = _mock_cursor()
    with patch.object(db, "_get_conn", return_value=conn):
        db.save_scan(
            {
                "scan_id": "scan-1",
                "subscription_id": "sub-1",
                "started_at": "2026-08-22T00:00:00Z",
                "completed_at": "2026-08-22T00:05:00Z",
                "total_findings": 0,
                "findings": [],
                "failed_rule_ids": [],
            }
        )

    executed_sql = conn.cursor.return_value.execute.call_args_list[0][0][0]
    # The base snapshot (framework provenance) is still COALESCE-protected...
    assert "COALESCE(" in executed_sql
    assert "scans.compliance_mapping_snapshot, EXCLUDED.compliance_mapping_snapshot" in executed_sql
    # ...but _scan_rule_outcomes is re-merged in from EXCLUDED on every write,
    # not frozen inside that same COALESCE.
    assert "jsonb_build_object" in executed_sql
    assert "'_scan_rule_outcomes', EXCLUDED.compliance_mapping_snapshot -> '_scan_rule_outcomes'" in executed_sql


def test_get_compliance_score_reflects_retry_that_clears_a_previously_failed_rule(tmp_path, monkeypatch):
    """Mirrors the row state across a replay: the upsert's jsonb merge keeps
    attempt 1's framework provenance but replaces _scan_rule_outcomes with
    whichever attempt actually wrote the current row. A rule that failed on
    attempt 1 and ran cleanly on a retry must stop reading as NOT_EVALUATED
    once that merge has happened - not keep reporting the stale first-attempt
    failure forever. Also proves the reverse: a rule that passed attempt 1
    and failed on a retry must not keep silently scoring as PASS."""
    controls = {"AZ-TEST-001": _control("1.1", "direct")}
    provenance = {
        "framework": "Test Framework",
        "version": "1.0",
        "mapping_pack_version": "1.0.0",
        "mapping_pack_status": "current",
        "mapping_pack_source": "test fixture",
        "mapping_pack_published": "2026-08-22",
        "controls": controls,
        finding_module._CONTENT_HASH_KEY: finding_module._compute_mapping_pack_content_hash(controls),
    }

    # _scan_rule_outcomes lives at the top level of the snapshot (as
    # save_scan() writes it), a sibling of each per-framework entry - not
    # nested inside "testfw" - since a rule failing to complete is scan-wide,
    # not framework-specific.

    # -- forward direction: failed on attempt 1, clean on the retry --------
    after_attempt_1 = {"testfw": provenance, "_scan_rule_outcomes": {"failed_rule_ids": ["AZ-TEST-001"]}}
    after_retry_clean = {"testfw": provenance}

    db, conn, framework_file = _patched_db_with_framework(
        tmp_path, controls, {"scan_id": "scan-1", "compliance_mapping_snapshot": after_attempt_1}, []
    )
    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    monkeypatch.setitem(finding_module.FRAMEWORK_FILE_MAP, "testfw", framework_file)
    with patch.object(db, "_get_conn", return_value=conn):
        result = db.get_compliance_score("testfw")
    assert result["controls"][0]["status"] == "NOT_EVALUATED"

    db2, conn2, _ = _patched_db_with_framework(
        tmp_path, controls, {"scan_id": "scan-1", "compliance_mapping_snapshot": after_retry_clean}, []
    )
    with patch.object(db2, "_get_conn", return_value=conn2):
        result2 = db2.get_compliance_score("testfw")
    assert result2["controls"][0]["status"] == "PASS"

    # -- reverse direction: clean on attempt 1, failed on the retry --------
    after_attempt_1_clean = {"testfw": provenance}
    after_retry_failed = {"testfw": provenance, "_scan_rule_outcomes": {"failed_rule_ids": ["AZ-TEST-001"]}}

    db3, conn3, _ = _patched_db_with_framework(
        tmp_path, controls, {"scan_id": "scan-1", "compliance_mapping_snapshot": after_attempt_1_clean}, []
    )
    with patch.object(db3, "_get_conn", return_value=conn3):
        result3 = db3.get_compliance_score("testfw")
    assert result3["controls"][0]["status"] == "PASS"

    db4, conn4, _ = _patched_db_with_framework(
        tmp_path, controls, {"scan_id": "scan-1", "compliance_mapping_snapshot": after_retry_failed}, []
    )
    with patch.object(db4, "_get_conn", return_value=conn4):
        result4 = db4.get_compliance_score("testfw")
    assert result4["controls"][0]["status"] == "NOT_EVALUATED"


# ── Route-level: /api/compliance/<framework> must degrade to 200, not 500,
#    when there is genuinely no scan evidence yet ──────────────────────────


def test_route_returns_200_for_no_scan_data(client, auth_headers):
    db = MagicMock()
    db.get_compliance_score.return_value = {
        "framework": "Test Framework",
        "version": "1.0",
        "status": "NO_SCAN_DATA",
        "message": "No completed scan is available yet.",
        "total_controls": 3,
        "in_scope_controls": 0,
        "excluded_controls": 0,
        "passed": 0,
        "failed": 0,
        "score_percent": None,
        "controls": [],
    }
    with patch.object(compliance_route, "_get_db", return_value=db):
        resp = client.get("/api/compliance/cis", headers=auth_headers)

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "NO_SCAN_DATA"
    assert body["score_percent"] is None


def test_route_reports_mapping_metadata_fields(client, auth_headers):
    db = MagicMock()
    db.get_compliance_score.return_value = {
        "framework": "Test Framework",
        "version": "1.0",
        "mapping_pack_version": "1.0.0",
        "mapping_pack_status": "current",
        "mapping_pack_source": "test",
        "mapping_pack_published": "2026-08-22",
        "scan_id": "scan-1",
        "evaluation_basis": "...",
        "total_controls": 1,
        "in_scope_controls": 1,
        "excluded_controls": 0,
        "passed": 1,
        "failed": 0,
        "score_percent": 100,
        "controls": [
            {
                "rule_id": "AZ-TEST-001",
                "control_id": "1.1",
                "control_name": "Control 1.1",
                "status": "PASS",
                "mapping_type": "direct",
                "evidence_type": "automated_configuration_scan",
                "primary_source": "test source",
                "rationale": "test rationale",
                "owner": None,
                "review_status": "pending_review",
                "review_date": None,
            }
        ],
    }
    with patch.object(compliance_route, "_get_db", return_value=db):
        resp = client.get("/api/compliance/cis", headers=auth_headers)

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["mapping_pack_version"] == "1.0.0"
    assert body["controls"][0]["mapping_type"] == "direct"
    assert body["controls"][0]["rationale"] == "test rationale"


# ── subscription_id scoping: a shared-database deployment must never return
#    another subscription's latest scan/score ──────────────────────────────


def test_get_compliance_score_filters_latest_scan_by_subscription_id(tmp_path, monkeypatch):
    """When a subscription_id is given, the "latest completed scan" lookup
    must be scoped to it - otherwise a shared database returns whichever
    subscription happened to scan most recently, not this caller's own."""
    for key, filename in finding_module.FRAMEWORK_FILE_MAP.items():
        _write_framework(tmp_path, filename, {})
    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)

    db = _db()
    conn = MagicMock()
    conn.cursor.return_value = _mock_cursor(fetchone_return=None)
    with patch.object(db, "_get_conn", return_value=conn):
        db.get_compliance_score("cis", subscription_id="11111111-1111-1111-1111-111111111111")

    executed_sql, params = conn.cursor.return_value.execute.call_args[0]
    assert "subscription_id = %s" in executed_sql
    assert params == ("11111111-1111-1111-1111-111111111111",)


def test_get_compliance_score_without_subscription_id_is_unfiltered(tmp_path, monkeypatch):
    """No subscription_id given (the caller couldn't resolve one) falls back
    to the prior unfiltered behaviour rather than raising."""
    for key, filename in finding_module.FRAMEWORK_FILE_MAP.items():
        _write_framework(tmp_path, filename, {})
    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)

    db = _db()
    conn = MagicMock()
    conn.cursor.return_value = _mock_cursor(fetchone_return=None)
    with patch.object(db, "_get_conn", return_value=conn):
        db.get_compliance_score("cis")

    call_args = conn.cursor.return_value.execute.call_args[0]
    executed_sql = call_args[0]
    assert "subscription_id" not in executed_sql
    assert len(call_args) == 1  # no params tuple - the query has no placeholders


def test_route_passes_subscription_id_query_param_to_get_compliance_score(client, auth_headers):
    db = MagicMock()
    db.get_compliance_score.return_value = {"status": "NO_SCAN_DATA", "controls": [], "score_percent": None}
    with patch.object(compliance_route, "_get_db", return_value=db):
        resp = client.get(
            "/api/compliance/cis?subscription_id=11111111-1111-1111-1111-111111111111", headers=auth_headers
        )

    assert resp.status_code == 200
    db.get_compliance_score.assert_called_once_with("cis", subscription_id="11111111-1111-1111-1111-111111111111")


def test_route_falls_back_to_env_subscription_id(client, auth_headers, monkeypatch):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "22222222-2222-2222-2222-222222222222")
    db = MagicMock()
    db.get_compliance_score.return_value = {"status": "NO_SCAN_DATA", "controls": [], "score_percent": None}
    with patch.object(compliance_route, "_get_db", return_value=db):
        resp = client.get("/api/compliance/cis", headers=auth_headers)

    assert resp.status_code == 200
    db.get_compliance_score.assert_called_once_with("cis", subscription_id="22222222-2222-2222-2222-222222222222")


def test_get_compliance_score_never_returns_another_subscriptions_scan(tmp_path, monkeypatch):
    """End-to-end shape of the cross-tenant leak: a shared database holds a
    completed scan for two subscriptions, and subscription B's scan is the
    most recent. Calling get_compliance_score() for subscription A must read
    A's snapshot, never B's most-recent-overall row."""
    sub_a = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    sub_b = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    controls = {"AZ-TEST-001": _control("1.1", "direct")}
    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    framework_file = "test_fw.json"
    _write_framework(tmp_path, framework_file, controls)
    monkeypatch.setitem(finding_module.FRAMEWORK_FILE_MAP, "testfw", framework_file)

    # Row store keyed by subscription_id. B has a finding for AZ-TEST-001
    # (would score FAIL); A is clean (would score PASS). "Latest overall"
    # with no filter would be B.
    rows = {
        sub_a: {"scan_id": "scan-a", "compliance_mapping_snapshot": None},
        sub_b: {"scan_id": "scan-b", "compliance_mapping_snapshot": None},
    }
    findings_by_scan = {"scan-a": [], "scan-b": [("AZ-TEST-001", "HIGH", "Storage", 1)]}

    class _TenantAwareCursor:
        def __init__(self):
            self._scan_id = None

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def execute(self, sql, params=None):
            if "FROM scans" in sql:
                # Honour the subscription_id filter the query must carry.
                assert "subscription_id = %s" in sql, "scan lookup is not scoped by subscription_id"
                assert params and len(params) == 1, "subscription_id was not bound as a parameter"
                self._row = rows.get(params[0])
                self._scan_id = self._row["scan_id"] if self._row else None
                self._mode = "scan"
            else:
                self._mode = "findings"

        def fetchone(self):
            return self._row if self._mode == "scan" else None

        def fetchall(self):
            return findings_by_scan.get(self._scan_id, []) if self._mode == "findings" else []

    conn = MagicMock()
    conn.cursor.return_value = _TenantAwareCursor()
    db = _db()
    with patch.object(db, "_get_conn", return_value=conn):
        result = db.get_compliance_score("testfw", subscription_id=sub_a)

    # A's own clean scan -> PASS. If B's row had leaked through we'd see FAIL.
    assert result["controls"][0]["status"] == "PASS"
    assert result["failed"] == 0
