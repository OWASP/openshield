"""Offline CLI contract checks."""

import json
from types import SimpleNamespace

from openshield import cli

SUBSCRIPTION = "00000000-0000-0000-0000-000000000001"


def test_cli_completed_findings_exit_zero(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_preflight", lambda *args: None)

    class Engine:
        def __init__(self, subscription_id):
            self.client = SimpleNamespace(credential=SimpleNamespace(get_token=lambda *args: object()))

        def run_scan(self):
            return {
                "scan_id": "scan-1",
                "subscription_id": SUBSCRIPTION,
                "status": "completed",
                "total_findings": 1,
                "findings": [{"severity": "HIGH", "rule_id": "AZ-TEST-001", "resource_id": "resource-1"}],
                "failed_rule_ids": [],
            }

    monkeypatch.setattr("scanner.engine.ScanEngine", Engine)
    assert cli.main(["scan", "--subscription-id", SUBSCRIPTION]) == 0
    assert "[HIGH] AZ-TEST-001" in capsys.readouterr().out
    assert cli.main(["scan", "--subscription-id", SUBSCRIPTION, "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["total_findings"] == 1


def test_cli_failed_rules_are_incomplete(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_preflight", lambda *args: None)

    class Engine:
        def __init__(self, subscription_id):
            self.client = SimpleNamespace(credential=SimpleNamespace(get_token=lambda *args: object()))

        def run_scan(self):
            return {
                "scan_id": "scan-2",
                "subscription_id": SUBSCRIPTION,
                "status": "completed",
                "total_findings": 0,
                "findings": [],
                "failed_rule_ids": ["AZ-TEST-002"],
            }

    monkeypatch.setattr("scanner.engine.ScanEngine", Engine)
    assert cli.main(["scan", "--subscription-id", SUBSCRIPTION, "--format", "json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "incomplete"
    assert result["failed_rule_ids"] == ["AZ-TEST-002"]


def test_cli_missing_subscription_is_error(monkeypatch, capsys):
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    assert cli.main(["scan", "--format", "json"]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "invalid_configuration"


def test_cli_subscription_preflight_fails_closed(monkeypatch, capsys):
    from azure.core.exceptions import HttpResponseError

    class Engine:
        def __init__(self, subscription_id):
            self.client = SimpleNamespace(credential=object())

        def run_scan(self):
            raise AssertionError("scan must not run without subscription access")

    monkeypatch.setattr("scanner.engine.ScanEngine", Engine)
    monkeypatch.setattr(cli, "_preflight", lambda *args: (_ for _ in ()).throw(HttpResponseError("denied")))
    assert cli.main(["scan", "--subscription-id", SUBSCRIPTION, "--format", "json"]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "subscription_unavailable"


def test_preflight_checks_subscription_access(monkeypatch):
    scopes = []
    checked = []
    credential = SimpleNamespace(get_token=lambda scope: scopes.append(scope))
    monkeypatch.setattr(
        cli,
        "SubscriptionClient",
        lambda supplied: SimpleNamespace(
            subscriptions=SimpleNamespace(get=lambda subscription: checked.append(subscription))
        ),
    )
    cli._preflight(credential, SUBSCRIPTION)
    assert scopes == ["https://management.azure.com/.default"]
    assert checked == [SUBSCRIPTION]


def test_cli_redacts_authentication_exception(monkeypatch, capsys):
    from azure.core.exceptions import ClientAuthenticationError

    class Engine:
        def __init__(self, subscription_id):
            self.client = SimpleNamespace(credential=object())

    monkeypatch.setattr("scanner.engine.ScanEngine", Engine)
    monkeypatch.setattr(
        cli,
        "_preflight",
        lambda *args: (_ for _ in ()).throw(ClientAuthenticationError("client_secret=do-not-print")),
    )
    assert cli.main(["scan", "--subscription-id", SUBSCRIPTION, "--format", "json"]) == 2
    output = capsys.readouterr().out
    assert json.loads(output)["status"] == "authentication_failed"
    assert "do-not-print" not in output


def test_cli_uses_subscription_environment_fallback(monkeypatch, capsys):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUBSCRIPTION)
    monkeypatch.setattr(cli, "_preflight", lambda *args: None)

    class Engine:
        def __init__(self, subscription_id):
            assert subscription_id == SUBSCRIPTION
            self.client = SimpleNamespace(credential=object())

        def run_scan(self):
            return {
                "scan_id": "scan-3",
                "subscription_id": SUBSCRIPTION,
                "status": "completed",
                "total_findings": 0,
                "findings": [],
                "failed_rule_ids": [],
            }

    monkeypatch.setattr("scanner.engine.ScanEngine", Engine)
    assert cli.main(["scan"]) == 0
    assert "Status: completed" in capsys.readouterr().out
