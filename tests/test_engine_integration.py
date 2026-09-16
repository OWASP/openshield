"""Offline integration tests for scanner.engine.ScanEngine.

ScanEngine.__init__ hardcodes ``self.client = AzureClient(subscription_id)``,
so there is no constructor injection point for a mock. These tests monkeypatch
``scanner.engine.AzureClient`` to return a configured MockAzureClient before
instantiating the engine, then exercise run_scan() end-to-end with no network.
"""

from pathlib import Path

import pytest

import scanner.engine as engine_mod
from openshield.severity import SeverityContractError, score_findings
from scanner.engine import ScanEngine
from tests.helpers.mock_azure import MockAzureClient, make_resource

_SUB = "00000000-0000-0000-0000-000000000001"
_RG = "rg-test"


class _OfflineCredential:
    """A credential whose get_token raises, so the handful of rules that build
    their own Azure SDK/Graph clients inside scan() fail fast OFFLINE (no real
    network egress) and are caught by their own try/except. This keeps the
    whole-engine integration test deterministic and network-free."""

    def get_token(self, *scopes, **kwargs):
        raise RuntimeError("offline test: no Azure access")


def _offline_mock():
    client = MockAzureClient()
    client.credential = _OfflineCredential()
    return client


def _patch_engine_client(monkeypatch, client):
    """Force ScanEngine to use the given client instead of a real AzureClient."""
    monkeypatch.setattr(engine_mod, "AzureClient", lambda subscription_id: client)


def _storage_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.Storage/storageAccounts/{name}"


def _nsg_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.Network/networkSecurityGroups/{name}"


def test_engine_loads_all_57_rules(monkeypatch):
    """The engine must dynamically load the complete rule set."""
    _patch_engine_client(monkeypatch, _offline_mock())
    eng = ScanEngine(_SUB)
    assert len(eng.rules) >= 57
    # Every loaded rule must expose a callable scan() and a RULE_ID.
    for rule in eng.rules:
        assert callable(getattr(rule, "scan", None))
        assert getattr(rule, "RULE_ID", None)


def test_engine_discovery_matches_ci_and_ignores_misnamed_modules(monkeypatch, tmp_path):
    """Only CI-validated az_*.py modules may execute at scan time."""
    (tmp_path / "az_valid_001.py").write_text(
        'RULE_ID = "AZ-VALID-001"\nSEVERITY = "LOW"\n\ndef scan(azure_client, subscription_id):\n    return []\n',
        encoding="utf-8",
    )
    (tmp_path / "scratch_test.py").write_text(
        'def scan(azure_client, subscription_id):\n    raise AssertionError("must not load")\n',
        encoding="utf-8",
    )
    (tmp_path / "_network_common.py").write_text(
        'def scan(azure_client, subscription_id):\n    raise AssertionError("must not load")\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(engine_mod, "RULES_DIR", Path(tmp_path))
    _patch_engine_client(monkeypatch, _offline_mock())

    eng = ScanEngine(_SUB)

    assert [rule.RULE_ID for rule in eng.rules] == ["AZ-VALID-001"]


@pytest.mark.parametrize("severity", ["INFORMATIONAL", "URGENT"])
def test_engine_rejects_noncanonical_rule_declarations(monkeypatch, tmp_path, severity):
    (tmp_path / "az_invalid_001.py").write_text(
        f'RULE_ID = "AZ-INVALID-001"\nSEVERITY = "{severity}"\n\n'
        "def scan(azure_client, subscription_id):\n    return []\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(engine_mod, "RULES_DIR", Path(tmp_path))
    _patch_engine_client(monkeypatch, _offline_mock())

    with pytest.raises(SeverityContractError):
        ScanEngine(_SUB)


def test_engine_run_scan_result_is_self_consistent(monkeypatch):
    """total_findings, the findings list, and score must be mutually consistent."""
    client = _offline_mock()
    # Seed a couple of flagged resources so the scan is non-empty but bounded.
    client.set_storage_accounts(
        [
            make_resource(
                id=_storage_id("public-sa"),
                name="public-sa",
                allow_blob_public_access=True,
                enable_https_traffic_only=False,
                sku=make_resource(name="Standard_LRS"),
                location="eastus",
            ),
        ]
    )
    _patch_engine_client(monkeypatch, client)

    eng = ScanEngine(_SUB)
    result = eng.run_scan()

    assert result["status"] == "completed"
    assert result["subscription_id"] == _SUB
    assert result["total_findings"] == len(result["findings"])
    assert result["total_findings"] > 0  # the public storage account triggers findings

    # Score is 100 minus severity-weighted deductions, floored at 0.
    assert result["score"] == score_findings(result["findings"])
    assert 0 <= result["score"] <= 100

    # Every finding is tagged with the scan_id and a detected_at timestamp.
    for f in result["findings"]:
        assert f["scan_id"] == result["scan_id"]
        assert "detected_at" in f


def test_engine_empty_subscription_is_consistent(monkeypatch):
    """A subscription with no resources still completes consistently.

    Note: it does NOT score 100 — several rules flag the *absence* of a control
    (e.g. AZ-IDN-002 flags "no Conditional Access MFA policy"), so an empty
    subscription legitimately produces a small number of findings. The result
    must still be internally consistent.
    """
    _patch_engine_client(monkeypatch, _offline_mock())
    eng = ScanEngine(_SUB)
    result = eng.run_scan()
    assert result["status"] == "completed"
    assert result["total_findings"] == len(result["findings"])
    assert 0 <= result["score"] <= 100
    # AZ-IDN-002 is absence-based: no CA policy configured -> it fires.
    assert any(f["rule_id"] == "AZ-IDN-002" for f in result["findings"])


def test_engine_isolates_a_failing_rule(monkeypatch):
    """One rule raising inside scan() must not abort the whole scan.

    Demonstrates the OBSERVABILITY GAP: the failed rule is swallowed and the
    result dict has no field recording which rules errored, so a partial scan
    is indistinguishable from a fully clean one.
    """
    _patch_engine_client(monkeypatch, _offline_mock())
    eng = ScanEngine(_SUB)
    assert len(eng.rules) >= 45

    # Force the first loaded rule to raise when scanned.
    def _boom(*args, **kwargs):
        raise RuntimeError("simulated rule failure")

    monkeypatch.setattr(eng.rules[0], "scan", _boom)

    result = eng.run_scan()  # must not raise
    assert result["status"] == "completed"
    # The other rules still ran (empty mock -> no findings) and the scan
    # completed. Crucially, there is NO field in the result naming the failed
    # rule -- this is the observability gap flagged in the validation report.
    assert "errored_rules" not in result
    assert "rules_failed" not in result
    assert "errors" not in result
