"""Rule regression tests for the identity rules AZ-IDN-001 .. AZ-IDN-009.

AZ-IDN-001/002 read data through MockAzureClient accessors. AZ-IDN-003..007
call Microsoft Graph via ``requests.get`` — those tests monkeypatch
``requests.get`` with a small URL router. AZ-IDN-008/009 instantiate Azure
management SDK clients inside scan() — those tests monkeypatch the SDK class.
No real network calls are ever made.
"""

import sys
from types import SimpleNamespace

import requests

import scanner.rules.az_idn_001 as az_idn_001
import scanner.rules.az_idn_002 as az_idn_002
import scanner.rules.az_idn_003 as az_idn_003
import scanner.rules.az_idn_004 as az_idn_004
import scanner.rules.az_idn_005 as az_idn_005
import scanner.rules.az_idn_006 as az_idn_006
import scanner.rules.az_idn_007 as az_idn_007
import scanner.rules.az_idn_008 as az_idn_008
import scanner.rules.az_idn_009 as az_idn_009
from tests.helpers.mock_azure import make_resource


class _Resp:
    """Minimal fake ``requests`` response."""

    def __init__(self, json_data, status_code=200):
        self._json = json_data
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._json


def _install_router(monkeypatch, routes):
    """Patch requests.get with a substring->response router.

    ``routes`` is a list of (url_substring, _Resp) pairs, checked in order.
    """

    def fake_get(url, *args, **kwargs):
        for needle, resp in routes:
            if needle in url:
                return resp
        raise AssertionError(f"unexpected URL in test: {url}")

    monkeypatch.setattr(requests, "get", fake_get)


_REQUIRED_FIELDS = {
    "rule_id",
    "rule_name",
    "severity",
    "category",
    "resource_id",
    "resource_name",
    "resource_type",
    "description",
    "remediation",
    "playbook",
    "frameworks",
    "metadata",
}

_SUB = "00000000-0000-0000-0000-000000000001"
_OWNER_ROLE_GUID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
_CONTRIBUTOR_ROLE_GUID = "b24988ac-6180-42a0-ab88-20f7382dd24c"
_ROLE_DEF_BASE = f"/subscriptions/{_SUB}/providers/Microsoft.Authorization/roleDefinitions"


def _assignment(role_guid, principal_id, assign_id):
    return make_resource(
        id=f"/subscriptions/{_SUB}/providers/Microsoft.Authorization/roleAssignments/{assign_id}",
        role_definition_id=f"{_ROLE_DEF_BASE}/{role_guid}",
        principal_id=principal_id,
        scope=f"/subscriptions/{_SUB}",
    )


def test_idn_001_compliant_returns_no_findings(mock_azure, subscription_id):
    """A service principal with a non-Owner role must produce no findings."""
    assignment = _assignment(_CONTRIBUTOR_ROLE_GUID, "sp-contributor-abc123", "assign-001")
    mock_azure.set_service_principals([assignment])
    findings = az_idn_001.scan(mock_azure, subscription_id)
    assert findings == []


def test_idn_001_noncompliant_returns_one_finding(mock_azure, subscription_id):
    """A service principal holding the Owner role must produce exactly one finding."""
    assignment = _assignment(_OWNER_ROLE_GUID, "sp-owner-def456", "assign-002")
    mock_azure.set_service_principals([assignment])
    findings = az_idn_001.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    finding = findings[0]
    assert _REQUIRED_FIELDS.issubset(finding.keys())
    assert finding["rule_id"] == "AZ-IDN-001"
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "Identity"
    assert finding["resource_name"] == "sp-owner-def456"
    assert finding["metadata"]["principal_id"] == "sp-owner-def456"


_GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"


# ── AZ-IDN-002: MFA enforced on admins via Conditional Access ───────────────


def test_idn_002_compliant_policy_enforces_mfa_returns_no_findings(mock_azure, subscription_id):
    """A CA policy that is enabled, requires MFA, and covers all users is compliant."""
    policy = {
        "state": "enabled",
        "grantControls": {"builtInControls": ["mfa"]},
        "conditions": {"users": {"includeUsers": ["All"]}},
    }
    mock_azure.set_conditional_access_policies([policy])
    assert az_idn_002.scan(mock_azure, subscription_id) == []


def test_idn_002_noncompliant_no_policies_returns_one_finding(mock_azure, subscription_id):
    """No Conditional Access policies at all must produce exactly one finding."""
    mock_azure.set_conditional_access_policies([])
    findings = az_idn_002.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-IDN-002"
    assert findings[0]["severity"] == "HIGH"


# ── AZ-IDN-003: guest invitations not restricted ───────────────────────────


def test_idn_003_compliant_restricted_invites_returns_no_findings(mock_azure, subscription_id, monkeypatch):
    _install_router(
        monkeypatch,
        [
            ("authorizationPolicy", _Resp({"id": "authPol", "allowInvitesFrom": "adminsAndGuestInviters"})),
        ],
    )
    assert az_idn_003.scan(mock_azure, subscription_id) == []


def test_idn_003_noncompliant_everyone_can_invite_returns_one_finding(mock_azure, subscription_id, monkeypatch):
    _install_router(
        monkeypatch,
        [
            ("authorizationPolicy", _Resp({"id": "authPol", "allowInvitesFrom": "everyone"})),
        ],
    )
    findings = az_idn_003.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-IDN-003"
    assert findings[0]["severity"] == "MEDIUM"


# ── AZ-IDN-004: no PIM for admin roles ──────────────────────────────────────


def test_idn_004_compliant_role_has_pim_returns_no_findings(mock_azure, subscription_id, monkeypatch):
    role_defs = {"value": [{"id": "rd-ga", "displayName": "Global Administrator"}]}
    schedules = {"value": [{"roleDefinitionId": "rd-ga"}]}
    _install_router(
        monkeypatch,
        [
            ("roleDefinitions", _Resp(role_defs)),
            ("roleEligibilitySchedules", _Resp(schedules)),
        ],
    )
    assert az_idn_004.scan(mock_azure, subscription_id) == []


def test_idn_004_noncompliant_role_without_pim_returns_finding(mock_azure, subscription_id, monkeypatch):
    role_defs = {"value": [{"id": "rd-ga", "displayName": "Global Administrator"}]}
    schedules = {"value": []}
    _install_router(
        monkeypatch,
        [
            ("roleEligibilitySchedules", _Resp(schedules)),  # check more specific first
            ("roleDefinitions", _Resp(role_defs)),
        ],
    )
    findings = az_idn_004.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-IDN-004"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["resource_name"] == "Global Administrator"


# ── AZ-IDN-005: guest with high-privilege role ──────────────────────────────


def test_idn_005_compliant_member_user_returns_no_findings(mock_azure, subscription_id, monkeypatch):
    role_defs = {"value": [{"id": "rd-ga", "displayName": "Global Administrator"}]}
    assignments = {"value": [{"id": "a1", "roleDefinitionId": "rd-ga", "principalId": "u1"}]}
    _install_router(
        monkeypatch,
        [
            ("/users/", _Resp({"id": "u1", "displayName": "Member User", "userType": "Member"})),
            ("roleDefinitions", _Resp(role_defs)),
            ("roleAssignments", _Resp(assignments)),
        ],
    )
    assert az_idn_005.scan(mock_azure, subscription_id) == []


def test_idn_005_noncompliant_guest_admin_returns_finding(mock_azure, subscription_id, monkeypatch):
    role_defs = {"value": [{"id": "rd-ga", "displayName": "Global Administrator"}]}
    assignments = {"value": [{"id": "a1", "roleDefinitionId": "rd-ga", "principalId": "g1"}]}
    _install_router(
        monkeypatch,
        [
            (
                "/users/",
                _Resp(
                    {
                        "id": "g1",
                        "displayName": "Guest Admin",
                        "userPrincipalName": "guest@ext.com",
                        "userType": "Guest",
                    }
                ),
            ),
            ("roleDefinitions", _Resp(role_defs)),
            ("roleAssignments", _Resp(assignments)),
        ],
    )
    findings = az_idn_005.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-IDN-005"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["resource_name"] == "Guest Admin"


# ── AZ-IDN-006: stale / non-expiring SP client secret ───────────────────────


def test_idn_006_compliant_fresh_secret_returns_no_findings(mock_azure, subscription_id, monkeypatch):
    apps = {
        "value": [
            {
                "id": "app1",
                "displayName": "App One",
                "appId": "client-1",
                "passwordCredentials": [
                    {
                        "keyId": "k1",
                        "hint": "ab",
                        "startDateTime": "2099-01-01T00:00:00Z",
                        "endDateTime": "2099-02-01T00:00:00Z",
                    }
                ],
            }
        ]
    }
    mock_azure.set_applications(apps["value"])
    assert az_idn_006.scan(mock_azure, subscription_id) == []


def test_idn_006_noncompliant_secret_no_expiry_returns_finding(mock_azure, subscription_id, monkeypatch):
    apps = {
        "value": [
            {
                "id": "app1",
                "displayName": "App One",
                "appId": "client-1",
                "passwordCredentials": [
                    {
                        "keyId": "k1",
                        "hint": "ab",
                        "startDateTime": "2020-01-01T00:00:00Z",
                        "endDateTime": None,
                    }
                ],
            }
        ]
    }
    mock_azure.set_applications(apps["value"])
    findings = az_idn_006.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-IDN-006"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["metadata"]["no_expiry"] is True


def test_idn_006_malformed_end_date_time_does_not_log_key_id(mock_azure, subscription_id, monkeypatch, caplog):
    """CodeQL alert #31 (py/clear-text-logging-sensitive-data): the debug log
    for a malformed endDateTime must not include the raw endDateTime value or
    keyId — neither is needed to diagnose a date-parsing failure, and Graph
    API credential fields should never be echoed into logs verbatim."""
    sentinel_key_id = "sentinel-key-id-should-not-appear-in-logs"
    sentinel_end_date = "sentinel-malformed-end-date-should-not-appear-in-logs"
    apps = {
        "value": [
            {
                "id": "app1",
                "displayName": "App One",
                "appId": "client-1",
                "passwordCredentials": [
                    {
                        "keyId": sentinel_key_id,
                        "hint": "ab",
                        "startDateTime": "2020-01-01T00:00:00Z",
                        "endDateTime": sentinel_end_date,
                    }
                ],
            }
        ]
    }
    mock_azure.set_applications(apps["value"])
    with caplog.at_level("DEBUG", logger="scanner.rules.az_idn_006"):
        findings = az_idn_006.scan(mock_azure, subscription_id)

    # Malformed endDateTime alone doesn't matter here: the secret is already stale by age.
    assert len(findings) == 1
    assert sentinel_key_id not in caplog.text
    assert sentinel_end_date not in caplog.text


# ── AZ-IDN-007: active user with no MFA registered ──────────────────────────


def test_idn_007_compliant_user_with_mfa_returns_no_findings(mock_azure, subscription_id, monkeypatch):
    regs = {"value": [{"id": "u1", "userPrincipalName": "a@x.com", "isEnabled": True, "isMfaRegistered": True}]}
    _install_router(monkeypatch, [("credentialUserRegistrationDetails", _Resp(regs))])
    assert az_idn_007.scan(mock_azure, subscription_id) == []


def test_idn_007_noncompliant_user_without_mfa_returns_finding(mock_azure, subscription_id, monkeypatch):
    regs = {
        "value": [
            {
                "id": "u1",
                "userDisplayName": "No MFA User",
                "userPrincipalName": "a@x.com",
                "isEnabled": True,
                "isMfaRegistered": False,
            }
        ]
    }
    _install_router(monkeypatch, [("credentialUserRegistrationDetails", _Resp(regs))])
    findings = az_idn_007.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-IDN-007"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["resource_name"] == "No MFA User"


def test_idn_007_disabled_user_without_mfa_returns_no_findings(mock_azure, subscription_id, monkeypatch):
    """A disabled user account without MFA registered must not be flagged —
    the rule targets active users only, since a disabled account cannot be
    used to sign in regardless of its MFA state."""
    regs = {
        "value": [
            {
                "id": "u2",
                "userDisplayName": "Disabled No MFA User",
                "userPrincipalName": "disabled@x.com",
                "isEnabled": False,
                "isMfaRegistered": False,
            }
        ]
    }
    _install_router(monkeypatch, [("credentialUserRegistrationDetails", _Resp(regs))])
    assert az_idn_007.scan(mock_azure, subscription_id) == []


# ── AZ-IDN-008: custom RBAC role with wildcard permissions ──────────────────


def _install_fake_auth_client(monkeypatch, roles):
    fake_module = SimpleNamespace(
        AuthorizationManagementClient=lambda *a, **k: SimpleNamespace(
            role_definitions=SimpleNamespace(list=lambda **kw: list(roles))
        )
    )
    monkeypatch.setitem(sys.modules, "azure.mgmt.authorization", fake_module)


def test_idn_008_compliant_specific_actions_returns_no_findings(mock_azure, subscription_id, monkeypatch):
    role = make_resource(
        role_name="ReaderPlus",
        name="rd1",
        id="/rd1",
        permissions=[make_resource(actions=["Microsoft.Storage/*/read"])],
        assignable_scopes=[f"/subscriptions/{_SUB}"],
    )
    _install_fake_auth_client(monkeypatch, [role])
    assert az_idn_008.scan(mock_azure, subscription_id) == []


def test_idn_008_noncompliant_wildcard_action_returns_finding(mock_azure, subscription_id, monkeypatch):
    role = make_resource(
        role_name="GodMode",
        name="rd2",
        id="/rd2",
        permissions=[make_resource(actions=["*"])],
        assignable_scopes=[f"/subscriptions/{_SUB}"],
    )
    _install_fake_auth_client(monkeypatch, [role])
    findings = az_idn_008.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-IDN-008"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["resource_name"] == "GodMode"


# ── AZ-IDN-009: no activity-log alert for role-assignment changes ───────────


def _install_fake_monitor_client(monkeypatch, alerts):
    fake_module = SimpleNamespace(
        MonitorManagementClient=lambda *a, **k: SimpleNamespace(
            activity_log_alerts=SimpleNamespace(list_by_subscription_id=lambda: list(alerts))
        )
    )
    monkeypatch.setitem(sys.modules, "azure.mgmt.monitor", fake_module)


def test_idn_009_compliant_alert_present_returns_no_findings(mock_azure, subscription_id, monkeypatch):
    leaf = make_resource(field="operationName", equals="Microsoft.Authorization/roleAssignments/write")
    alert = make_resource(enabled=True, condition=make_resource(all_of=[leaf]))
    _install_fake_monitor_client(monkeypatch, [alert])
    assert az_idn_009.scan(mock_azure, subscription_id) == []


def test_idn_009_noncompliant_no_alert_returns_finding(mock_azure, subscription_id, monkeypatch):
    _install_fake_monitor_client(monkeypatch, [])
    findings = az_idn_009.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-IDN-009"
    assert findings[0]["severity"] == "MEDIUM"
