from datetime import datetime, timedelta, timezone

import pytest

from scanner.governance import GovernancePolicy
from scanner.rules import (
    az_gov_001,
    az_gov_002,
    az_gov_003,
    az_gov_004,
    az_gov_005,
    az_gov_006,
    az_gov_007,
    az_gov_008,
    az_gov_009,
    az_gov_010,
)
from scanner.rules import _governance_common as common

SUB = "sub"
SCOPE = "/subscriptions/sub"
RESOURCE = f"{SCOPE}/resourceGroups/prod/providers/Microsoft.Storage/storageAccounts/data"
OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"


@pytest.fixture
def policy():
    return GovernancePolicy(
        approved_management_group_ids=frozenset({"/providers/microsoft.management/managementgroups/prod"}),
        required_policy_initiatives=({"definition_id": "/definitions/base", "scope": SCOPE},),
        preventive_policy_definition_ids=frozenset({"/definitions/deny-public"}),
        allowed_preventive_effects=frozenset({"deny"}),
        production_resource_types=frozenset({"microsoft.storage/storageaccounts"}),
        production_tag="environment",
        production_tag_values=frozenset({"prod"}),
        maximum_subscription_owners=1,
        privileged_role_definition_ids=frozenset({OWNER}),
        approved_privileged_scopes=frozenset({f"{SCOPE}/resourcegroups/security"}),
        approved_provider_namespaces=frozenset({"microsoft.storage"}),
        ownership_tags=frozenset({"owner"}),
        drift_sla_days=30,
        excluded_resource_ids=frozenset(),
    )


@pytest.fixture
def run(monkeypatch, policy):
    def _run(module, snapshot):
        monkeypatch.setattr(common, "load_context", lambda *_args: (policy, snapshot))
        return module.scan(object(), SUB)

    return _run


def test_gov_001_hierarchy_compliant_and_noncompliant(run):
    good = {
        "hierarchy": [
            {"managementGroupAncestorsChain": [{"id": "/providers/Microsoft.Management/managementGroups/prod"}]}
        ]
    }
    assert run(az_gov_001, good) == []
    findings = run(az_gov_001, {"hierarchy": [{"managementGroupAncestorsChain": []}]})
    assert findings[0]["rule_id"] == "AZ-GOV-001"


def test_gov_002_required_initiative_scope(run):
    good = {
        "policy_assignments": [
            {
                "id": f"{SCOPE}/providers/Microsoft.Authorization/policyAssignments/base",
                "properties": {"policyDefinitionId": "/definitions/base"},
            }
        ]
    }
    assert run(az_gov_002, good) == []
    assert run(az_gov_002, {"policy_assignments": []})[0]["metadata"]["evidence"]["missing_assignments"]


def test_gov_003_only_confirmed_bad_effect_fails(run):
    definition = {
        "id": "/definitions/deny-public",
        "properties": {
            "parameters": {"effect": {"defaultValue": "Audit"}},
            "policyRule": {"then": {"effect": "[parameters('effect')]"}},
        },
    }
    assignment = {
        "id": f"{SCOPE}/providers/Microsoft.Authorization/policyAssignments/deny",
        "properties": {"policyDefinitionId": "/definitions/deny-public", "parameters": {}},
    }
    snapshot = {"policy_assignments": [assignment], "policy_definitions": [definition]}
    assert run(az_gov_003, snapshot)[0]["rule_id"] == "AZ-GOV-003"
    assignment["properties"]["parameters"]["effect"] = {"value": "Deny"}
    assert run(az_gov_003, snapshot) == []


def test_gov_004_exemption_metadata_and_expiration(run):
    future = (datetime.now(timezone.utc) + timedelta(days=20)).isoformat()
    good = {
        "policy_exemptions": [
            {
                "id": f"{SCOPE}/providers/Microsoft.Authorization/policyExemptions/approved",
                "properties": {"expiresOn": future, "metadata": {"owner": "team", "justification": "migration"}},
            }
        ]
    }
    assert run(az_gov_004, good) == []
    bad = {"policy_exemptions": [{"id": "exemption", "properties": {"metadata": {}}}]}
    assert set(run(az_gov_004, bad)[0]["metadata"]["evidence"]["missing_or_invalid"]) == {
        "owner",
        "justification",
        "valid expiration",
    }


def test_gov_005_honours_parent_lock(run):
    resource = {"id": RESOURCE, "type": "Microsoft.Storage/storageAccounts", "tags": {"Environment": "Prod"}}
    parent = f"{SCOPE}/resourceGroups/prod"
    lock = {"id": f"{parent}/providers/Microsoft.Authorization/locks/protect", "properties": {"level": "CanNotDelete"}}
    assert run(az_gov_005, {"resources": [resource], "locks": [lock]}) == []
    assert run(az_gov_005, {"resources": [resource], "locks": []})[0]["resource_id"] == RESOURCE


def test_gov_006_owner_threshold(run):
    def owner(name):
        return {
            "id": f"{SCOPE}/providers/Microsoft.Authorization/roleAssignments/{name}",
            "properties": {"roleDefinitionId": f"{SCOPE}/providers/Microsoft.Authorization/roleDefinitions/{OWNER}"},
        }

    def mg_owner(name):
        mg_scope = "/providers/Microsoft.Management/managementGroups/root"
        return {
            "id": f"{mg_scope}/providers/Microsoft.Authorization/roleAssignments/{name}",
            "properties": {"roleDefinitionId": f"{mg_scope}/providers/Microsoft.Authorization/roleDefinitions/{OWNER}"},
        }

    assert run(az_gov_006, {"role_assignments": [owner("one")]}) == []
    assert (
        run(az_gov_006, {"role_assignments": [owner("one"), owner("two")]})[0]["metadata"]["evidence"]["owner_count"]
        == 2
    )
    # Inherited management-group Owner must count toward the threshold.
    # The collector's atScope() returns both direct and MG-inherited assignments;
    # filtering to subscription scope alone silently misses this common pattern.
    assert (
        run(az_gov_006, {"role_assignments": [owner("direct"), mg_owner("inherited")]})[0]["metadata"]["evidence"][
            "owner_count"
        ]
        == 2
    )


def test_gov_007_privileged_scope(run):
    broad = {
        "id": f"{SCOPE}/providers/Microsoft.Authorization/roleAssignments/one",
        "properties": {"roleDefinitionId": f"/roleDefinitions/{OWNER}"},
    }
    finding = run(az_gov_007, {"role_assignments": [broad]})[0]
    assert finding["rule_id"] == "AZ-GOV-007"
    assert finding["metadata"]["effective_scope"] == SCOPE
    assert finding["metadata"]["permissions_required"]
    assert finding["metadata"]["unknown_reason"] is None


def test_gov_008_registered_provider_allowlist(run):
    providers = [
        {"namespace": "Microsoft.Storage", "registrationState": "Registered"},
        {"namespace": "Microsoft.Unapproved", "registrationState": "Registered"},
    ]
    findings = run(az_gov_008, {"providers": providers})
    assert len(findings) == 1
    assert "Microsoft.Unapproved" in findings[0]["resource_id"]


def test_gov_009_ownership_tag(run):
    resource = {"id": RESOURCE, "type": "Microsoft.Storage/storageAccounts", "tags": {"environment": "prod"}}
    assert run(az_gov_009, {"resources": [resource]})[0]["rule_id"] == "AZ-GOV-009"
    resource["tags"]["owner"] = "payments"
    assert run(az_gov_009, {"resources": [resource]}) == []


def test_gov_010_drift_sla_boundary(run):
    old = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
    boundary = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    recent = (datetime.now(timezone.utc) - timedelta(days=29)).isoformat()

    def state(timestamp):
        return {"complianceState": "NonCompliant", "timestamp": timestamp, "resourceId": RESOURCE}

    assert run(az_gov_010, {"policy_states": [state(old)]})[0]["rule_id"] == "AZ-GOV-010"
    assert run(az_gov_010, {"policy_states": [state(boundary)]}) == []
    assert run(az_gov_010, {"policy_states": [state(recent)]}) == []


def test_gov_003_missing_definitions_evidence_is_unknown(run):
    assignment = {
        "id": f"{SCOPE}/providers/Microsoft.Authorization/policyAssignments/deny",
        "properties": {"policyDefinitionId": "/definitions/deny-public", "parameters": {}},
    }
    assert run(az_gov_003, {"policy_assignments": [assignment], "policy_definitions": None}) == []


def test_gov_005_missing_locks_evidence_is_unknown(run):
    resource = {"id": RESOURCE, "type": "Microsoft.Storage/storageAccounts", "tags": {"Environment": "Prod"}}
    assert run(az_gov_005, {"resources": [resource], "locks": None}) == []


@pytest.mark.parametrize(
    "module,source",
    [
        (az_gov_001, "hierarchy"),
        (az_gov_002, "policy_assignments"),
        (az_gov_003, "policy_assignments"),
        (az_gov_004, "policy_exemptions"),
        (az_gov_005, "resources"),
        (az_gov_006, "role_assignments"),
        (az_gov_007, "role_assignments"),
        (az_gov_008, "providers"),
        (az_gov_009, "resources"),
        (az_gov_010, "policy_states"),
    ],
)
def test_missing_evidence_never_becomes_failure(run, module, source):
    assert run(module, {source: None}) == []
