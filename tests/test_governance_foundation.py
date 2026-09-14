import json
import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from scanner.governance import GovernanceCollector, load_governance_policy
from scanner.rules import _governance_common as common


def _valid_policy():
    return {
        "approved_management_group_ids": ["/providers/Microsoft.Management/managementGroups/prod"],
        "required_policy_initiatives": [{"definition_id": "/definitions/base", "scope": "/subscriptions/sub"}],
        "preventive_policy_definition_ids": ["/definitions/deny-public"],
        "allowed_preventive_effects": ["deny"],
        "production_resource_types": ["Microsoft.Storage/storageAccounts"],
        "production_tag": "environment",
        "production_tag_values": ["prod"],
        "maximum_subscription_owners": 2,
        "privileged_role_definition_ids": ["owner-role"],
        "approved_privileged_scopes": ["/subscriptions/sub/resourcegroups/security"],
        "approved_provider_namespaces": ["Microsoft.Storage"],
        "ownership_tags": ["owner"],
        "drift_sla_days": 30,
        "excluded_resource_ids": [],
    }


def test_policy_loader_is_strict_and_normalises(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(_valid_policy()), encoding="utf-8")
    policy = load_governance_policy(path)
    assert policy.production_resource_types == frozenset({"microsoft.storage/storageaccounts"})
    assert policy.maximum_subscription_owners == 2

    invalid = _valid_policy()
    invalid["unexpected"] = True
    path.write_text(json.dumps(invalid), encoding="utf-8")
    with pytest.raises(ValueError, match="missing or unsupported"):
        load_governance_policy(path)


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class _Session:
    def __init__(self):
        self.get_responses = [
            _Response({"value": [{"id": "one"}], "nextLink": "https://management.azure.com/next"}),
            _Response({"value": [{"id": "two"}]}),
        ]

    def get(self, *_args, **_kwargs):
        return self.get_responses.pop(0)

    def post(self, _url, **kwargs):
        if "query" in kwargs.get("json", {}):
            return _Response({"data": []})
        return _Response({"value": []})


def test_collector_follows_arm_next_link():
    credential = SimpleNamespace(get_token=lambda _scope: SimpleNamespace(token="secret"))
    collector = GovernanceCollector(credential, "sub", session=_Session())
    assert collector._get_all("/first") == [{"id": "one"}, {"id": "two"}]


def test_collector_returns_none_for_transport_failure():
    class BrokenSession:
        @staticmethod
        def get(*_args, **_kwargs):
            raise TypeError("bad transport")

    credential = SimpleNamespace(get_token=lambda _scope: SimpleNamespace(token="secret"))
    collector = GovernanceCollector(credential, "sub", session=BrokenSession())
    assert collector._get_all("/first") is None


def test_resource_graph_collector_follows_skip_token():
    class GraphSession:
        def __init__(self):
            self.requests = []

        def post(self, _url, **kwargs):
            self.requests.append(kwargs["json"])
            if len(self.requests) == 1:
                return _Response({"data": [{"id": "one"}], "$skipToken": "next-page"})
            return _Response({"data": [{"id": "two"}]})

    credential = SimpleNamespace(get_token=lambda _scope: SimpleNamespace(token="secret"))
    session = GraphSession()
    collector = GovernanceCollector(credential, "sub", session=session)
    assert collector._post_graph("Resources | project id") == [{"id": "one"}, {"id": "two"}]
    assert session.requests[1]["options"]["$skipToken"] == "next-page"


# Bug fixes


def test_post_graph_stops_on_repeated_skip_token():
    """_post_graph must not loop forever when the API returns the same $skipToken twice."""
    call_count = 0

    class LoopingSession:
        def post(self, _url, **_kwargs):
            nonlocal call_count
            call_count += 1
            return _Response({"data": [{"id": str(call_count)}], "$skipToken": "stuck-token"})

    credential = SimpleNamespace(get_token=lambda _scope: SimpleNamespace(token="secret"))
    collector = GovernanceCollector(credential, "sub", session=LoopingSession())
    result = collector._post_graph("Resources | project id")
    assert result is not None
    assert call_count <= 3


def test_post_values_filters_non_dict_items_instead_of_aborting():
    """_post_values must skip non-dict items and keep the rest, not return None."""
    class MixedSession:
        def post(self, _url, **_kwargs):
            return _Response({"value": [{"id": "good"}, None, {"id": "also-good"}]})

    credential = SimpleNamespace(get_token=lambda _scope: SimpleNamespace(token="secret"))
    collector = GovernanceCollector(credential, "sub", session=MixedSession())
    result = collector._post_values("/some/path")
    assert result == [{"id": "good"}, {"id": "also-good"}]


def test_load_context_snapshot_is_keyed_per_subscription(tmp_path):
    """Using the same azure_client with a different subscription_id must not reuse a stale snapshot."""
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps({
        "approved_management_group_ids": ["/providers/Microsoft.Management/managementGroups/prod"],
        "required_policy_initiatives": [],
        "preventive_policy_definition_ids": [],
        "allowed_preventive_effects": ["deny"],
        "production_resource_types": ["Microsoft.Storage/storageAccounts"],
        "production_tag": "environment",
        "production_tag_values": ["prod"],
        "maximum_subscription_owners": 3,
        "privileged_role_definition_ids": [],
        "approved_privileged_scopes": [],
        "approved_provider_namespaces": ["Microsoft.Storage"],
        "ownership_tags": ["owner"],
        "drift_sla_days": 30,
        "excluded_resource_ids": [],
    }), encoding="utf-8")

    snapshots_collected = []

    def fake_collect(sub_id):
        snap = {"scope": f"/subscriptions/{sub_id}", "sub": sub_id}
        snapshots_collected.append(sub_id)
        return snap

    credential = SimpleNamespace(get_token=lambda _scope: SimpleNamespace(token="t"))
    client = SimpleNamespace(credential=credential)

    with patch.dict(os.environ, {common.POLICY_ENV: str(policy_path)}):
        with patch("scanner.rules._governance_common.GovernanceCollector") as MockCollector:
            MockCollector.return_value.collect.side_effect = [
                {"scope": "/subscriptions/sub-a"},
                {"scope": "/subscriptions/sub-b"},
            ]
            result_a = common.load_context(client, "sub-a", "AZ-GOV-001")
            result_b = common.load_context(client, "sub-b", "AZ-GOV-001")

    assert result_a is not None
    assert result_b is not None
    _, snapshot_a = result_a
    _, snapshot_b = result_b
    assert snapshot_a["scope"] == "/subscriptions/sub-a"
    assert snapshot_b["scope"] == "/subscriptions/sub-b"
    assert MockCollector.return_value.collect.call_count == 2


@pytest.mark.parametrize("bad_url", [
    "https://management.azure.com.attacker.example/next",
    "https://management.azure.com@attacker.example/next",
    "https://management.azure.com:8443/next",
    "http://management.azure.com/next",
])
def test_collector_rejects_lookalike_arm_continuation(bad_url):
    """_get_all and _post_values must return None when a continuation URL is not the exact ARM origin."""
    credential = SimpleNamespace(get_token=lambda _scope: SimpleNamespace(token="secret"))

    class LookalikeLinkSession:
        def get(self, *_args, **_kwargs):
            return _Response({"value": [{"id": "page1"}], "nextLink": bad_url})

        def post(self, *_args, **_kwargs):
            return _Response({"value": [{"id": "page1"}], "nextLink": bad_url})

    collector = GovernanceCollector(credential, "sub", session=LookalikeLinkSession())
    assert collector._get_all("/first") is None
    assert collector._post_values("/first") is None


def test_collector_valid_arm_continuation_is_followed():
    """A legitimate ARM nextLink on the exact origin must still be followed."""
    credential = SimpleNamespace(get_token=lambda _scope: SimpleNamespace(token="secret"))

    class TwoPageSession:
        def __init__(self):
            self._calls = 0

        def get(self, *_args, **_kwargs):
            self._calls += 1
            if self._calls == 1:
                return _Response({"value": [{"id": "p1"}], "nextLink": "https://management.azure.com/next?skip=1"})
            return _Response({"value": [{"id": "p2"}]})

    collector = GovernanceCollector(credential, "sub", session=TwoPageSession())
    result = collector._get_all("/first")
    assert result == [{"id": "p1"}, {"id": "p2"}]


def test_collector_userinfo_url_rejected():
    """A URL with userinfo (@ notation) must be rejected even if hostname appears correct after the @."""
    from scanner.governance import _is_safe_arm_continuation
    assert not _is_safe_arm_continuation("https://user@management.azure.com/next")
    assert not _is_safe_arm_continuation("https://management.azure.com@attacker.com/next")
    assert _is_safe_arm_continuation("https://management.azure.com/subscriptions?api=2023")


def test_load_context_policy_file_read_once_per_subscription(tmp_path):
    """load_governance_policy must be called only once even when 10 rules call load_context."""
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps({
        "approved_management_group_ids": ["/providers/Microsoft.Management/managementGroups/prod"],
        "required_policy_initiatives": [],
        "preventive_policy_definition_ids": [],
        "allowed_preventive_effects": ["deny"],
        "production_resource_types": ["Microsoft.Storage/storageAccounts"],
        "production_tag": "environment",
        "production_tag_values": ["prod"],
        "maximum_subscription_owners": 3,
        "privileged_role_definition_ids": [],
        "approved_privileged_scopes": [],
        "approved_provider_namespaces": ["Microsoft.Storage"],
        "ownership_tags": ["owner"],
        "drift_sla_days": 30,
        "excluded_resource_ids": [],
    }), encoding="utf-8")

    credential = SimpleNamespace(get_token=lambda _scope: SimpleNamespace(token="t"))
    client = SimpleNamespace(credential=credential)

    with patch.dict(os.environ, {common.POLICY_ENV: str(policy_path)}):
        with patch("scanner.rules._governance_common.GovernanceCollector") as MockCollector:
            MockCollector.return_value.collect.return_value = {"scope": "/subscriptions/sub"}
            with patch("scanner.rules._governance_common.load_governance_policy", wraps=load_governance_policy) as mock_load:
                rule_ids = [f"AZ-GOV-{i:03d}" for i in range(1, 11)]
                for rule_id in rule_ids:
                    common.load_context(client, "sub", rule_id)
                assert mock_load.call_count == 1
