"""Tests for privileged access and identity rules AZ-IDN-016 through AZ-IDN-025."""

from datetime import datetime, timedelta, timezone


from scanner.rules import (
    az_idn_016,
    az_idn_017,
    az_idn_018,
    az_idn_019,
    az_idn_020,
    az_idn_021,
    az_idn_022,
    az_idn_023,
    az_idn_024,
    az_idn_025,
)

_GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"
_SEC_ADMIN_ROLE_ID = "194ae4cb-b126-40b2-bd5b-6091b380977d"
_AZURE_MGMT_APP_ID = "797f4846-ba00-4fd7-ba43-dac1f8f63013"


# ── helpers ────────────────────────────────────────────────────────────────────


def priv_user(**overrides):
    base = {
        "userId": "user-1",
        "userDisplayName": "Alice Admin",
        "userPrincipalName": "alice@example.com",
        "accountEnabled": True,
        "lastSignInDateTime": datetime.now(timezone.utc).isoformat(),
        "roleId": _GLOBAL_ADMIN_ROLE_ID,
        "roleName": "Global Administrator",
    }
    base.update(overrides)
    return base


def mfa_user(**overrides):
    base = {
        "userId": "user-1",
        "userDisplayName": "Alice Admin",
        "userPrincipalName": "alice@example.com",
        "authMethodTypes": ["fido2"],
    }
    base.update(overrides)
    return base


def pim_assignment(**overrides):
    base = {
        "principalId": "user-1",
        "roleId": _GLOBAL_ADMIN_ROLE_ID,
        "assignmentType": "Eligible",
    }
    base.update(overrides)
    return base


def ca_policy(**overrides):
    import copy

    base = {
        "id": "policy-1",
        "displayName": "Test Policy",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"], "excludeUsers": [], "excludeServicePrincipals": []},
            "applications": {"includeApplications": ["All"]},
            "clientAppTypes": ["all"],
        },
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
    }
    result = copy.deepcopy(base)
    if "conditions" in overrides:
        result["conditions"].update(overrides.pop("conditions"))
    result.update(overrides)
    return result


def priv_group(**overrides):
    base = {"id": "group-1", "displayName": "Privileged Group", "ownerCount": 1}
    base.update(overrides)
    return base


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


def assert_valid_finding(finding):
    assert _REQUIRED_FIELDS.issubset(finding.keys())
    assert finding["frameworks"]


# ── AZ-IDN-016: phishing-resistant MFA ────────────────────────────────────────


def test_idn_016_fido2_method_is_compliant(mock_azure, subscription_id):
    mock_azure.set_privileged_users_mfa_methods([mfa_user(authMethodTypes=["fido2"])])
    assert az_idn_016.scan(mock_azure, subscription_id) == []


def test_idn_016_whfb_method_is_compliant(mock_azure, subscription_id):
    mock_azure.set_privileged_users_mfa_methods([mfa_user(authMethodTypes=["windowsHelloForBusiness"])])
    assert az_idn_016.scan(mock_azure, subscription_id) == []


def test_idn_016_x509_method_is_compliant(mock_azure, subscription_id):
    mock_azure.set_privileged_users_mfa_methods([mfa_user(authMethodTypes=["x509Certificate"])])
    assert az_idn_016.scan(mock_azure, subscription_id) == []


def test_idn_016_totp_only_returns_finding(mock_azure, subscription_id):
    mock_azure.set_privileged_users_mfa_methods([mfa_user(authMethodTypes=["microsoftAuthenticator"])])
    findings = az_idn_016.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["registered_methods"] == ["microsoftAuthenticator"]
    assert_valid_finding(findings[0])


def test_idn_016_no_methods_returns_finding(mock_azure, subscription_id):
    mock_azure.set_privileged_users_mfa_methods([mfa_user(authMethodTypes=[])])
    findings = az_idn_016.scan(mock_azure, subscription_id)
    assert len(findings) == 1


def test_idn_016_empty_inventory_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_privileged_users_mfa_methods([])
    assert az_idn_016.scan(mock_azure, subscription_id) == []


def test_idn_016_api_failure_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_privileged_users_mfa_methods(None)
    assert az_idn_016.scan(mock_azure, subscription_id) == []


def test_idn_016_user_without_id_is_skipped(mock_azure, subscription_id):
    mock_azure.set_privileged_users_mfa_methods([mfa_user(userId="", authMethodTypes=[])])
    assert az_idn_016.scan(mock_azure, subscription_id) == []


# ── AZ-IDN-017: Global Admin permanent assignment ──────────────────────────────


def test_idn_017_pim_eligible_admin_is_compliant(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members([priv_user()])
    mock_azure.set_pim_role_assignments([pim_assignment(assignmentType="Eligible")])
    assert az_idn_017.scan(mock_azure, subscription_id) == []


def test_idn_017_permanent_admin_without_pim_returns_finding(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members([priv_user()])
    mock_azure.set_pim_role_assignments([])
    findings = az_idn_017.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["role_name"] == "Global Administrator"
    assert_valid_finding(findings[0])


def test_idn_017_non_global_admin_role_not_flagged(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members([priv_user(roleId=_SEC_ADMIN_ROLE_ID, roleName="Security Administrator")])
    mock_azure.set_pim_role_assignments([])
    assert az_idn_017.scan(mock_azure, subscription_id) == []


def test_idn_017_pim_unavailable_is_unknown(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members([priv_user()])
    mock_azure.set_pim_role_assignments(None)
    assert az_idn_017.scan(mock_azure, subscription_id) == []


def test_idn_017_member_inventory_failure_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members(None)
    assert az_idn_017.scan(mock_azure, subscription_id) == []


def test_idn_017_empty_members_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members([])
    mock_azure.set_pim_role_assignments([])
    assert az_idn_017.scan(mock_azure, subscription_id) == []


# ── AZ-IDN-018: privileged roles outside PIM ───────────────────────────────────


def test_idn_018_pim_eligible_member_is_compliant(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members([priv_user()])
    mock_azure.set_pim_role_assignments([pim_assignment()])
    assert az_idn_018.scan(mock_azure, subscription_id) == []


def test_idn_018_no_pim_returns_finding(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members([priv_user()])
    mock_azure.set_pim_role_assignments([])
    findings = az_idn_018.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["role_id"] == _GLOBAL_ADMIN_ROLE_ID
    assert_valid_finding(findings[0])


def test_idn_018_active_pim_not_eligible_returns_finding(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members([priv_user()])
    mock_azure.set_pim_role_assignments([pim_assignment(assignmentType="Active")])
    findings = az_idn_018.scan(mock_azure, subscription_id)
    assert len(findings) == 1


def test_idn_018_member_inventory_failure_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members(None)
    assert az_idn_018.scan(mock_azure, subscription_id) == []


def test_idn_018_empty_inventory_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members([])
    mock_azure.set_pim_role_assignments([])
    assert az_idn_018.scan(mock_azure, subscription_id) == []


# ── AZ-IDN-019: stale privileged accounts ─────────────────────────────────────


def _recent():
    return (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()


def _stale():
    return (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()


def test_idn_019_recent_sign_in_is_compliant(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members([priv_user(lastSignInDateTime=_recent())])
    assert az_idn_019.scan(mock_azure, subscription_id) == []


def test_idn_019_stale_sign_in_returns_finding(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members([priv_user(lastSignInDateTime=_stale())])
    findings = az_idn_019.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["days_inactive"] >= 90
    assert_valid_finding(findings[0])


def test_idn_019_no_sign_in_record_returns_finding(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members([priv_user(lastSignInDateTime=None)])
    findings = az_idn_019.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["days_inactive"] is None


def test_idn_019_disabled_account_not_flagged(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members([priv_user(lastSignInDateTime=_stale(), accountEnabled=False)])
    assert az_idn_019.scan(mock_azure, subscription_id) == []


def test_idn_019_api_failure_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members(None)
    assert az_idn_019.scan(mock_azure, subscription_id) == []


def test_idn_019_empty_inventory_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members([])
    assert az_idn_019.scan(mock_azure, subscription_id) == []


def test_idn_019_malformed_date_returns_finding(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members([priv_user(lastSignInDateTime="not-a-date")])
    findings = az_idn_019.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["days_inactive"] is None


# ── AZ-IDN-020: emergency access accounts ──────────────────────────────────────


def test_idn_020_two_break_glass_accounts_is_compliant(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members(
        [
            priv_user(userId="bg-1", userPrincipalName="emergency1@example.com"),
            priv_user(userId="bg-2", userPrincipalName="breakglass2@example.com"),
        ]
    )
    assert az_idn_020.scan(mock_azure, subscription_id) == []


def test_idn_020_one_break_glass_is_insufficient(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members(
        [
            priv_user(userId="bg-1", userPrincipalName="emergency@example.com"),
            priv_user(userId="user-2", userPrincipalName="alice@example.com"),
        ]
    )
    findings = az_idn_020.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["break_glass_accounts_found"] == 1
    assert_valid_finding(findings[0])


def test_idn_020_no_break_glass_returns_finding(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members([priv_user()])
    findings = az_idn_020.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["break_glass_accounts_found"] == 0


def test_idn_020_break_glass_in_display_name_detected(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members(
        [
            priv_user(userId="bg-1", userDisplayName="Break-Glass Account 1"),
            priv_user(userId="bg-2", userDisplayName="Break-Glass Account 2"),
        ]
    )
    assert az_idn_020.scan(mock_azure, subscription_id) == []


def test_idn_020_api_failure_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members(None)
    assert az_idn_020.scan(mock_azure, subscription_id) == []


def test_idn_020_non_global_admin_break_glass_not_counted(mock_azure, subscription_id):
    mock_azure.set_privileged_role_members(
        [
            priv_user(userId="bg-1", userPrincipalName="emergency@example.com", roleId=_SEC_ADMIN_ROLE_ID),
            priv_user(userId="bg-2", userPrincipalName="breakglass@example.com", roleId=_SEC_ADMIN_ROLE_ID),
        ]
    )
    findings = az_idn_020.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["global_admin_count"] == 0


# ── AZ-IDN-021: block legacy auth ─────────────────────────────────────────────


def test_idn_021_policy_blocking_other_clients_is_compliant(mock_azure, subscription_id):
    policy = ca_policy(
        conditions={"clientAppTypes": ["exchangeActiveSync", "other"]},
        grantControls={"operator": "OR", "builtInControls": ["block"]},
    )
    mock_azure.set_conditional_access_policies([policy])
    assert az_idn_021.scan(mock_azure, subscription_id) == []


def test_idn_021_policy_covering_all_clients_is_compliant(mock_azure, subscription_id):
    policy = ca_policy(
        conditions={"clientAppTypes": ["all"]},
        grantControls={"operator": "OR", "builtInControls": ["block"]},
    )
    mock_azure.set_conditional_access_policies([policy])
    assert az_idn_021.scan(mock_azure, subscription_id) == []


def test_idn_021_no_policy_returns_finding(mock_azure, subscription_id):
    mock_azure.set_conditional_access_policies([])
    findings = az_idn_021.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert_valid_finding(findings[0])


def test_idn_021_disabled_policy_returns_finding(mock_azure, subscription_id):
    policy = ca_policy(
        state="disabled",
        conditions={"clientAppTypes": ["other"]},
        grantControls={"operator": "OR", "builtInControls": ["block"]},
    )
    mock_azure.set_conditional_access_policies([policy])
    findings = az_idn_021.scan(mock_azure, subscription_id)
    assert len(findings) == 1


def test_idn_021_mfa_policy_not_blocking_is_non_compliant(mock_azure, subscription_id):
    policy = ca_policy(
        conditions={"clientAppTypes": ["browser", "mobileAppsAndDesktopClients"]},
        grantControls={"operator": "OR", "builtInControls": ["mfa"]},
    )
    mock_azure.set_conditional_access_policies([policy])
    findings = az_idn_021.scan(mock_azure, subscription_id)
    assert len(findings) == 1


def test_idn_021_mfa_only_policy_for_legacy_clients_is_non_compliant(mock_azure, subscription_id):
    policy = ca_policy(
        conditions={"clientAppTypes": ["exchangeActiveSync", "other"]},
        grantControls={"operator": "OR", "builtInControls": ["mfa"]},
    )
    mock_azure.set_conditional_access_policies([policy])
    assert len(az_idn_021.scan(mock_azure, subscription_id)) == 1


# ── AZ-IDN-022: CA protects Azure management ──────────────────────────────────


def test_idn_022_all_apps_policy_is_compliant(mock_azure, subscription_id):
    policy = ca_policy(
        conditions={"applications": {"includeApplications": ["All"]}},
        grantControls={"operator": "OR", "builtInControls": ["mfa"]},
    )
    mock_azure.set_conditional_access_policies([policy])
    assert az_idn_022.scan(mock_azure, subscription_id) == []


def test_idn_022_azure_mgmt_app_id_policy_is_compliant(mock_azure, subscription_id):
    policy = ca_policy(
        conditions={"applications": {"includeApplications": [_AZURE_MGMT_APP_ID]}},
        grantControls={"operator": "OR", "builtInControls": ["mfa"]},
    )
    mock_azure.set_conditional_access_policies([policy])
    assert az_idn_022.scan(mock_azure, subscription_id) == []


def test_idn_022_no_policy_returns_finding(mock_azure, subscription_id):
    mock_azure.set_conditional_access_policies([])
    findings = az_idn_022.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert_valid_finding(findings[0])


def test_idn_022_policy_for_different_app_returns_finding(mock_azure, subscription_id):
    policy = ca_policy(
        conditions={"applications": {"includeApplications": ["other-app-id"]}},
        grantControls={"operator": "OR", "builtInControls": ["mfa"]},
    )
    mock_azure.set_conditional_access_policies([policy])
    findings = az_idn_022.scan(mock_azure, subscription_id)
    assert len(findings) == 1


def test_idn_022_disabled_policy_returns_finding(mock_azure, subscription_id):
    policy = ca_policy(
        state="disabled",
        conditions={"applications": {"includeApplications": ["All"]}},
        grantControls={"operator": "OR", "builtInControls": ["mfa"]},
    )
    mock_azure.set_conditional_access_policies([policy])
    findings = az_idn_022.scan(mock_azure, subscription_id)
    assert len(findings) == 1


# ── AZ-IDN-023: Identity Protection risk policies ─────────────────────────────


def test_idn_023_both_policies_enabled_is_compliant(mock_azure, subscription_id):
    mock_azure.set_identity_protection_policies(
        {
            "userRiskPolicy": {"isEnabled": True, "riskLevel": "medium"},
            "signInRiskPolicy": {"isEnabled": True, "riskLevel": "medium"},
        }
    )
    assert az_idn_023.scan(mock_azure, subscription_id) == []


def test_idn_023_user_risk_disabled_returns_finding(mock_azure, subscription_id):
    mock_azure.set_identity_protection_policies(
        {
            "userRiskPolicy": {"isEnabled": False, "riskLevel": "none"},
            "signInRiskPolicy": {"isEnabled": True, "riskLevel": "medium"},
        }
    )
    findings = az_idn_023.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert "userRiskPolicy" in findings[0]["metadata"]["disabled_policies"]
    assert_valid_finding(findings[0])


def test_idn_023_sign_in_risk_disabled_returns_finding(mock_azure, subscription_id):
    mock_azure.set_identity_protection_policies(
        {
            "userRiskPolicy": {"isEnabled": True, "riskLevel": "medium"},
            "signInRiskPolicy": {"isEnabled": False, "riskLevel": "none"},
        }
    )
    findings = az_idn_023.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert "signInRiskPolicy" in findings[0]["metadata"]["disabled_policies"]


def test_idn_023_both_disabled_returns_one_finding(mock_azure, subscription_id):
    mock_azure.set_identity_protection_policies(
        {
            "userRiskPolicy": {"isEnabled": False},
            "signInRiskPolicy": {"isEnabled": False},
        }
    )
    findings = az_idn_023.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert len(findings[0]["metadata"]["disabled_policies"]) == 2


def test_idn_023_api_failure_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_identity_protection_policies(None)
    assert az_idn_023.scan(mock_azure, subscription_id) == []


# ── AZ-IDN-024: workload identities excluded from CA ──────────────────────────


def test_idn_024_policy_including_service_principals_is_compliant(mock_azure, subscription_id):
    policy = ca_policy()
    policy["conditions"]["clientApplications"] = {
        "includeServicePrincipals": ["All"],
        "excludeServicePrincipals": [],
    }
    mock_azure.set_conditional_access_policies([policy])
    assert az_idn_024.scan(mock_azure, subscription_id) == []


def test_idn_024_all_sps_excluded_returns_finding(mock_azure, subscription_id):
    policy = ca_policy()
    policy["conditions"]["clientApplications"] = {
        "includeServicePrincipals": ["All"],
        "excludeServicePrincipals": ["All"],
    }
    mock_azure.set_conditional_access_policies([policy])
    findings = az_idn_024.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["all_exclude_workload_identities"] is True
    assert_valid_finding(findings[0])


def test_idn_024_no_enforcing_policies_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_conditional_access_policies([])
    assert az_idn_024.scan(mock_azure, subscription_id) == []


def test_idn_024_disabled_policy_not_counted(mock_azure, subscription_id):
    policy = ca_policy(state="disabled")
    policy["conditions"]["clientApplications"] = {
        "includeServicePrincipals": ["All"],
        "excludeServicePrincipals": ["All"],
    }
    mock_azure.set_conditional_access_policies([policy])
    assert az_idn_024.scan(mock_azure, subscription_id) == []


def test_idn_024_guest_user_exclusion_is_not_workload_exclusion(mock_azure, subscription_id):
    policy = ca_policy()
    policy["conditions"]["users"]["excludeUsers"] = ["GuestsOrExternalUsers"]
    policy["conditions"]["clientApplications"] = {
        "includeServicePrincipals": ["All"],
        "excludeServicePrincipals": [],
    }
    mock_azure.set_conditional_access_policies([policy])
    assert az_idn_024.scan(mock_azure, subscription_id) == []


# ── AZ-IDN-025: privileged groups governance ───────────────────────────────────


def test_idn_025_group_with_owner_is_compliant(mock_azure, subscription_id):
    mock_azure.set_privileged_groups([priv_group(ownerCount=1)])
    assert az_idn_025.scan(mock_azure, subscription_id) == []


def test_idn_025_group_with_multiple_owners_is_compliant(mock_azure, subscription_id):
    mock_azure.set_privileged_groups([priv_group(ownerCount=3)])
    assert az_idn_025.scan(mock_azure, subscription_id) == []


def test_idn_025_ownerless_group_returns_finding(mock_azure, subscription_id):
    mock_azure.set_privileged_groups([priv_group(ownerCount=0)])
    findings = az_idn_025.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["owner_count"] == 0
    assert_valid_finding(findings[0])


def test_idn_025_multiple_ownerless_groups_return_multiple_findings(mock_azure, subscription_id):
    mock_azure.set_privileged_groups(
        [
            priv_group(id="g1", ownerCount=0),
            priv_group(id="g2", ownerCount=0),
            priv_group(id="g3", ownerCount=2),
        ]
    )
    findings = az_idn_025.scan(mock_azure, subscription_id)
    assert len(findings) == 2


def test_idn_025_api_failure_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_privileged_groups(None)
    assert az_idn_025.scan(mock_azure, subscription_id) == []


def test_idn_025_empty_inventory_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_privileged_groups([])
    assert az_idn_025.scan(mock_azure, subscription_id) == []


def test_idn_025_group_without_id_is_skipped(mock_azure, subscription_id):
    mock_azure.set_privileged_groups([priv_group(id="", ownerCount=0)])
    assert az_idn_025.scan(mock_azure, subscription_id) == []
