import json
from types import SimpleNamespace

import pytest

from scanner.governance import GovernanceCollector, load_governance_policy


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
