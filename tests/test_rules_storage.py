"""Rule regression tests for AZ-STOR-001 and AZ-STOR-002.

Each test configures a MockAzureClient with a single fake storage account
and calls the rule's scan() function directly. No network calls are made.
"""

import scanner.rules.az_stor_001 as az_stor_001
import scanner.rules.az_stor_002 as az_stor_002
import scanner.rules.az_stor_003 as az_stor_003
import scanner.rules.az_stor_004 as az_stor_004
import scanner.rules.az_stor_005 as az_stor_005
import scanner.rules.az_stor_006 as az_stor_006
import scanner.rules.az_stor_007 as az_stor_007
import scanner.rules.az_stor_008 as az_stor_008
import scanner.rules.az_stor_009 as az_stor_009
import scanner.rules.az_stor_010 as az_stor_010
from scanner.evaluation import EvaluationStatus
from tests.helpers.mock_azure import make_resource

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
}

_SUB = "00000000-0000-0000-0000-000000000001"
_RG = "rg-test"


def _storage_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.Storage/storageAccounts/{name}"


def test_stor_001_compliant_returns_no_findings(mock_azure, subscription_id):
    """A storage account with public blob access disabled must produce no findings."""
    account = make_resource(
        id=_storage_id("compliant-storage"),
        name="compliant-storage",
        allow_blob_public_access=False,
    )
    mock_azure.set_storage_accounts([account])
    findings = az_stor_001.scan(mock_azure, subscription_id)
    assert findings == []


def test_stor_001_noncompliant_returns_one_finding(mock_azure, subscription_id):
    """A storage account with public blob access enabled must produce exactly one finding."""
    account = make_resource(
        id=_storage_id("public-storage"),
        name="public-storage",
        allow_blob_public_access=True,
    )
    mock_azure.set_storage_accounts([account])
    findings = az_stor_001.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    finding = findings[0]
    assert _REQUIRED_FIELDS.issubset(finding.keys())
    assert finding["rule_id"] == "AZ-STOR-001"
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "Storage"
    assert finding["resource_name"] == "public-storage"


def test_stor_002_compliant_returns_no_findings(mock_azure, subscription_id):
    """A storage account with HTTPS-only enabled must produce no findings."""
    account = make_resource(
        id=_storage_id("https-only-storage"),
        name="https-only-storage",
        enable_https_traffic_only=True,
    )
    mock_azure.set_storage_accounts([account])
    findings = az_stor_002.scan(mock_azure, subscription_id)
    assert findings == []


def test_stor_002_noncompliant_returns_one_finding(mock_azure, subscription_id):
    """A storage account that allows HTTP traffic must produce exactly one finding."""
    account = make_resource(
        id=_storage_id("http-allowed-storage"),
        name="http-allowed-storage",
        enable_https_traffic_only=False,
    )
    mock_azure.set_storage_accounts([account])
    findings = az_stor_002.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    finding = findings[0]
    assert _REQUIRED_FIELDS.issubset(finding.keys())
    assert finding["rule_id"] == "AZ-STOR-002"
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "Storage"
    assert finding["resource_name"] == "http-allowed-storage"


# ── AZ-STOR-003: no lifecycle management policy ─────────────────────────────


def test_stor_003_compliant_returns_no_findings(mock_azure, subscription_id):
    acct = make_resource(id=_storage_id("sa-lifecycle"), name="sa-lifecycle", location="eastus")
    mock_azure.set_storage_accounts([acct])
    mock_azure.set_storage_lifecycle_policy(_RG, "sa-lifecycle", True)
    assert az_stor_003.scan(mock_azure, subscription_id) == []


def test_stor_003_noncompliant_returns_one_finding(mock_azure, subscription_id):
    acct = make_resource(id=_storage_id("sa-nolifecycle"), name="sa-nolifecycle", location="eastus")
    mock_azure.set_storage_accounts([acct])
    mock_azure.set_storage_lifecycle_policy(_RG, "sa-nolifecycle", False)
    findings = az_stor_003.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-STOR-003"
    assert findings[0]["severity"] == "MEDIUM"


def test_stor_003_indeterminate_skips(mock_azure, subscription_id):
    """When lifecycle status is None (cannot determine) the rule must not flag."""
    acct = make_resource(id=_storage_id("sa-unknown"), name="sa-unknown", location="eastus")
    mock_azure.set_storage_accounts([acct])
    mock_azure.set_storage_lifecycle_policy(_RG, "sa-unknown", None)
    assert az_stor_003.scan(mock_azure, subscription_id) == []


# ── AZ-STOR-004: diagnostic logging disabled (per blob/queue/table) ─────────


def test_stor_004_compliant_all_services_logged_returns_no_findings(mock_azure, subscription_id):
    acct = make_resource(id=_storage_id("sa-logged"), name="sa-logged", location="eastus")
    mock_azure.set_storage_accounts([acct])
    for svc in ("blob", "queue", "table"):
        mock_azure.set_storage_service_logging(_RG, "sa-logged", svc, True)
    assert az_stor_004.scan(mock_azure, subscription_id) == []


def test_stor_004_noncompliant_blob_unlogged_returns_one_finding(mock_azure, subscription_id):
    acct = make_resource(id=_storage_id("sa-blobunlogged"), name="sa-blobunlogged", location="eastus")
    mock_azure.set_storage_accounts([acct])
    mock_azure.set_storage_service_logging(_RG, "sa-blobunlogged", "blob", False)
    mock_azure.set_storage_service_logging(_RG, "sa-blobunlogged", "queue", True)
    mock_azure.set_storage_service_logging(_RG, "sa-blobunlogged", "table", True)
    findings = az_stor_004.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-STOR-004"
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["metadata"]["service"] == "blob"


# ── AZ-STOR-005: not geo-redundant ──────────────────────────────────────────


def test_stor_005_compliant_grs_returns_no_findings(mock_azure, subscription_id):
    acct = make_resource(
        id=_storage_id("sa-grs"),
        name="sa-grs",
        location="eastus",
        sku=make_resource(name="Standard_GRS"),
    )
    mock_azure.set_storage_accounts([acct])
    assert az_stor_005.scan(mock_azure, subscription_id) == []


def test_stor_005_noncompliant_lrs_returns_one_finding(mock_azure, subscription_id):
    acct = make_resource(
        id=_storage_id("sa-lrs"),
        name="sa-lrs",
        location="eastus",
        sku=make_resource(name="Standard_LRS"),
    )
    mock_azure.set_storage_accounts([acct])
    findings = az_stor_005.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-STOR-005"
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["resource_name"] == "sa-lrs"


def test_stor_006_shared_key_enabled_returns_one_finding(mock_azure, subscription_id):
    account = make_resource(
        id=_storage_id("sa-shared-key"),
        name="sa-shared-key",
        allow_shared_key_access=True,
    )
    mock_azure.set_storage_accounts([account])
    findings = az_stor_006.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-STOR-006"


def test_stor_006_disabled_is_not_flagged(mock_azure, subscription_id):
    disabled = make_resource(id=_storage_id("sa-entra"), name="sa-entra", allow_shared_key_access=False)
    mock_azure.set_storage_accounts([disabled])
    assert az_stor_006.scan(mock_azure, subscription_id) == []


def test_stor_006_none_is_flagged_as_insecure_default(mock_azure, subscription_id):
    # Azure documents allow_shared_key_access=None as equivalent to True.
    account = make_resource(id=_storage_id("sa-default"), name="sa-default")
    mock_azure.set_storage_accounts([account])
    findings = az_stor_006.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-STOR-006"


def test_stor_007_tls_below_12_returns_one_finding(mock_azure, subscription_id):
    account = make_resource(id=_storage_id("sa-tls10"), name="sa-tls10", minimum_tls_version="TLS1_0")
    mock_azure.set_storage_accounts([account])
    findings = az_stor_007.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-STOR-007"


def test_stor_007_secure_is_not_flagged(mock_azure, subscription_id):
    secure = make_resource(id=_storage_id("sa-tls12"), name="sa-tls12", minimum_tls_version="TLS1_2")
    mock_azure.set_storage_accounts([secure])
    assert az_stor_007.scan(mock_azure, subscription_id) == []


def test_stor_007_none_is_flagged_as_tls10_default(mock_azure, subscription_id):
    # Azure documents unset minimum_tls_version as TLS 1.0.
    account = make_resource(id=_storage_id("sa-tls-default"), name="sa-tls-default")
    mock_azure.set_storage_accounts([account])
    findings = az_stor_007.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-STOR-007"


def test_stor_007_sdk_enum_tls10_is_flagged(mock_azure, subscription_id):
    # SDK may return an enum object; enum_str() must extract the underlying value.
    class _FakeTlsEnum:
        value = "TLS1_0"

        def __str__(self):
            return "MinimumTlsVersion.TLS1_0"

    account = make_resource(id=_storage_id("sa-tls-enum"), name="sa-tls-enum", minimum_tls_version=_FakeTlsEnum())
    mock_azure.set_storage_accounts([account])
    findings = az_stor_007.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-STOR-007"


def test_stor_008_required_cmk_missing_returns_finding(mock_azure, subscription_id):
    account = make_resource(
        id=_storage_id("sa-cmk"),
        name="sa-cmk",
        tags={"oshield:cmk-required": "true"},
        encryption=make_resource(key_source="Microsoft.Storage"),
    )
    mock_azure.set_storage_accounts([account])
    findings = az_stor_008.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-STOR-008"


def test_stor_008_cmk_or_unknown_is_not_flagged(mock_azure, subscription_id):
    compliant = make_resource(
        id=_storage_id("sa-cmk-ok"),
        name="sa-cmk-ok",
        tags={"oshield:cmk-required": "true"},
        encryption=make_resource(key_source="Microsoft.Keyvault"),
    )
    unknown = make_resource(
        id=_storage_id("sa-cmk-unknown"),
        name="sa-cmk-unknown",
        tags={"oshield:cmk-required": "true"},
    )
    mock_azure.set_storage_accounts([compliant, unknown])
    assert az_stor_008.scan(mock_azure, subscription_id) == []


def test_stor_009_required_container_without_policy_returns_finding(mock_azure, subscription_id):
    account = make_resource(id=_storage_id("sa-immutable"), name="sa-immutable")
    container = make_resource(
        name="critical-data",
        tags={"oshield:immutability-required": "true"},
        immutability_policy=None,
    )
    mock_azure.set_storage_accounts([account])
    mock_azure.set_blob_containers(_RG, "sa-immutable", [container])
    findings = az_stor_009.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-STOR-009"


def test_stor_009_policy_or_api_failure_is_not_flagged(mock_azure, subscription_id):
    account = make_resource(id=_storage_id("sa-immutable-ok"), name="sa-immutable-ok")
    policy = make_resource(state="Locked", immutability_period_since_creation_in_days=30)
    container = make_resource(
        name="critical-data",
        tags={"oshield:immutability-required": "true"},
        immutability_policy=policy,
    )
    mock_azure.set_storage_accounts([account])
    mock_azure.set_blob_containers(_RG, "sa-immutable-ok", [container])
    assert az_stor_009.scan(mock_azure, subscription_id) == []
    mock_azure.set_blob_containers(_RG, "sa-immutable-ok", None)
    assert az_stor_009.scan(mock_azure, subscription_id) == []


# ── AZ-STOR-010: storage account missing an approved Private Endpoint ────────


def _private_endpoint(status="Approved"):
    return make_resource(private_link_service_connection_state=make_resource(status=status))


def test_stor_010_approved_private_endpoint_returns_no_findings(mock_azure, subscription_id):
    """An account with an Approved Private Endpoint connection is compliant."""
    account = make_resource(
        id=_storage_id("sa-with-pe"),
        name="sa-with-pe",
        private_endpoint_connections=[_private_endpoint("Approved")],
    )
    mock_azure.set_storage_accounts([account])
    assert az_stor_010.scan(mock_azure, subscription_id) == []


def test_stor_010_public_access_disabled_is_not_applicable(mock_azure, subscription_id):
    """An account with public_network_access Disabled is already isolated — not flagged."""
    account = make_resource(
        id=_storage_id("sa-private-only"),
        name="sa-private-only",
        public_network_access="Disabled",
        private_endpoint_connections=[],
    )
    mock_azure.set_storage_accounts([account])
    assert az_stor_010.scan(mock_azure, subscription_id) == []


def test_stor_010_no_private_endpoint_returns_one_finding(mock_azure, subscription_id):
    """A publicly reachable account with no Private Endpoint must produce one HIGH finding."""
    account = make_resource(
        id=_storage_id("sa-public"),
        name="sa-public",
        public_network_access="Enabled",
        private_endpoint_connections=[],
    )
    mock_azure.set_storage_accounts([account])
    findings = az_stor_010.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    finding = findings[0]
    assert _REQUIRED_FIELDS.issubset(finding.keys())
    assert finding["rule_id"] == "AZ-STOR-010"
    assert finding["severity"] == "HIGH"
    assert finding["resource_name"] == "sa-public"


def test_stor_010_only_pending_private_endpoint_is_flagged(mock_azure, subscription_id):
    """A Private Endpoint connection that is not Approved does not count as coverage."""
    account = make_resource(
        id=_storage_id("sa-pending-pe"),
        name="sa-pending-pe",
        private_endpoint_connections=[_private_endpoint("Pending")],
    )
    mock_azure.set_storage_accounts([account])
    findings = az_stor_010.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-STOR-010"


def test_stor_010_unavailable_evidence_is_indeterminate_not_flagged(mock_azure, subscription_id):
    """When private_endpoint_connections is None (evidence unavailable, e.g. not populated
    or a permissions failure), the account is indeterminate and must not be flagged as a
    confirmed absence."""
    account = make_resource(
        id=_storage_id("sa-unknown-pe"),
        name="sa-unknown-pe",
        public_network_access="Enabled",
        private_endpoint_connections=None,
    )
    mock_azure.set_storage_accounts([account])
    assert az_stor_010.scan(mock_azure, subscription_id) == []


# ── evaluate(): coverage contract (#370) ────────────────────────────────────
#
# Inventory failure, empty inventory, finding shape and scan() parity are
# covered for every rule by tests/test_rule_evaluation_contract.py. These
# tests pin the rule-specific branches that scan() used to skip silently.


def _status(evaluations, resource_id):
    matches = [e for e in evaluations if e.resource_id == resource_id]
    assert len(matches) == 1, f"expected one evaluation for {resource_id}, got {len(matches)}"
    return matches[0].status, matches[0].reason_code


def test_stor_001_unset_public_access_is_unknown_not_pass(mock_azure, subscription_id):
    mock_azure.set_storage_accounts(
        [make_resource(id=_storage_id("sa-unset"), name="sa-unset", allow_blob_public_access=None)]
    )
    evaluations = az_stor_001.evaluate(mock_azure, subscription_id)
    assert _status(evaluations, _storage_id("sa-unset")) == (EvaluationStatus.UNKNOWN, "MISSING_PROPERTIES")


def test_stor_002_missing_field_is_unknown_and_none_still_fails(mock_azure, subscription_id):
    mock_azure.set_storage_accounts(
        [
            make_resource(id=_storage_id("sa-missing"), name="sa-missing"),
            make_resource(id=_storage_id("sa-none"), name="sa-none", enable_https_traffic_only=None),
        ]
    )
    evaluations = az_stor_002.evaluate(mock_azure, subscription_id)
    assert _status(evaluations, _storage_id("sa-missing")) == (EvaluationStatus.UNKNOWN, "MISSING_PROPERTIES")
    assert _status(evaluations, _storage_id("sa-none")) == (EvaluationStatus.FAIL, None)


def test_stor_003_unreadable_policy_and_missing_resource_group_are_unknown(mock_azure, subscription_id):
    no_rg_id = f"/subscriptions/{_SUB}/providers/Microsoft.Storage/storageAccounts/sa-norg"
    mock_azure.set_storage_accounts(
        [
            make_resource(id=_storage_id("sa-unread"), name="sa-unread", location="eastus"),
            make_resource(id=no_rg_id, name="sa-norg", location="eastus"),
        ]
    )
    mock_azure.set_storage_lifecycle_policy(_RG, "sa-unread", None)
    evaluations = az_stor_003.evaluate(mock_azure, subscription_id)
    assert _status(evaluations, _storage_id("sa-unread")) == (EvaluationStatus.UNKNOWN, "EVIDENCE_UNAVAILABLE")
    assert _status(evaluations, no_rg_id) == (EvaluationStatus.UNKNOWN, "MISSING_PROPERTIES")


def test_stor_004_reports_each_service_separately(mock_azure, subscription_id):
    mock_azure.set_storage_accounts([make_resource(id=_storage_id("sa-logs"), name="sa-logs", location="eastus")])
    mock_azure.set_storage_service_logging(_RG, "sa-logs", "blob", True)
    mock_azure.set_storage_service_logging(_RG, "sa-logs", "queue", False)
    mock_azure.set_storage_service_logging(_RG, "sa-logs", "table", None)
    evaluations = az_stor_004.evaluate(mock_azure, subscription_id)
    base = _storage_id("sa-logs")
    assert _status(evaluations, f"{base}/blobServices/default") == (EvaluationStatus.PASS, None)
    assert _status(evaluations, f"{base}/queueServices/default") == (EvaluationStatus.FAIL, None)
    assert _status(evaluations, f"{base}/tableServices/default") == (
        EvaluationStatus.UNKNOWN,
        "EVIDENCE_UNAVAILABLE",
    )
    assert {e.resource_type for e in evaluations} == {
        "Microsoft.Storage/storageAccounts/blobServices",
        "Microsoft.Storage/storageAccounts/queueServices",
        "Microsoft.Storage/storageAccounts/tableServices",
    }


def test_stor_005_missing_sku_is_unknown(mock_azure, subscription_id):
    mock_azure.set_storage_accounts([make_resource(id=_storage_id("sa-nosku"), name="sa-nosku", sku=None)])
    evaluations = az_stor_005.evaluate(mock_azure, subscription_id)
    assert _status(evaluations, _storage_id("sa-nosku")) == (EvaluationStatus.UNKNOWN, "MISSING_PROPERTIES")


def test_stor_006_account_without_id_is_unknown_instead_of_an_empty_id_finding(mock_azure, subscription_id):
    """scan() used to emit a finding with resource_id "" that could not be
    remediated and collided with every other ID-less finding."""
    mock_azure.set_storage_accounts([make_resource(id="", name="sa-noid", allow_shared_key_access=True)])
    evaluations = az_stor_006.evaluate(mock_azure, subscription_id)
    assert _status(evaluations, f"/subscriptions/{subscription_id}") == (
        EvaluationStatus.UNKNOWN,
        "MISSING_PROPERTIES",
    )
    assert az_stor_006.scan(mock_azure, subscription_id) == []


def test_stor_007_unrecognized_tls_value_is_unknown(mock_azure, subscription_id):
    mock_azure.set_storage_accounts(
        [make_resource(id=_storage_id("sa-weird"), name="sa-weird", minimum_tls_version="TLS9_9")]
    )
    evaluations = az_stor_007.evaluate(mock_azure, subscription_id)
    assert _status(evaluations, _storage_id("sa-weird")) == (EvaluationStatus.UNKNOWN, "UNRECOGNIZED_TLS_VERSION")


def test_stor_008_policy_exemptions_and_unknown_sources(mock_azure, subscription_id):
    mock_azure.set_storage_accounts(
        [
            make_resource(id=_storage_id("sa-untagged"), name="sa-untagged", tags={}),
            make_resource(
                id=_storage_id("sa-exempt"),
                name="sa-exempt",
                tags={"oshield:cmk-required": "true", "oshield:exception-approved": "true"},
            ),
            make_resource(
                id=_storage_id("sa-nosource"),
                name="sa-nosource",
                tags={"oshield:cmk-required": "true"},
                encryption=None,
            ),
            make_resource(
                id=_storage_id("sa-other"),
                name="sa-other",
                tags={"oshield:cmk-required": "true"},
                encryption=make_resource(key_source="Other"),
            ),
        ]
    )
    evaluations = az_stor_008.evaluate(mock_azure, subscription_id)
    assert _status(evaluations, _storage_id("sa-untagged")) == (EvaluationStatus.NOT_APPLICABLE, "POLICY_NOT_REQUIRED")
    assert _status(evaluations, _storage_id("sa-exempt")) == (EvaluationStatus.NOT_APPLICABLE, "APPROVED_EXCEPTION")
    assert _status(evaluations, _storage_id("sa-nosource")) == (EvaluationStatus.UNKNOWN, "MISSING_PROPERTIES")
    assert _status(evaluations, _storage_id("sa-other")) == (EvaluationStatus.UNKNOWN, "UNRECOGNIZED_KEY_SOURCE")


def test_stor_009_reports_each_container_and_account_level_gaps(mock_azure, subscription_id):
    locked = make_resource(state="Locked", immutability_period_since_creation_in_days=30)
    mock_azure.set_storage_accounts(
        [
            make_resource(id=_storage_id("sa-mixed"), name="sa-mixed"),
            make_resource(id=_storage_id("sa-empty"), name="sa-empty"),
            make_resource(id=_storage_id("sa-unlisted"), name="sa-unlisted"),
        ]
    )
    mock_azure.set_blob_containers(
        _RG,
        "sa-mixed",
        [
            make_resource(name="plain", tags={}, immutability_policy=None),
            make_resource(name="kept", tags={"oshield:immutability-required": "true"}, immutability_policy=locked),
            make_resource(name="open", tags={"oshield:immutability-required": "true"}, immutability_policy=None),
            make_resource(
                name="waived",
                tags={"oshield:immutability-required": "true", "oshield:exception-approved": "true"},
                immutability_policy=None,
            ),
        ],
    )
    mock_azure.set_blob_containers(_RG, "sa-empty", [])
    mock_azure.set_blob_containers(_RG, "sa-unlisted", None)
    evaluations = az_stor_009.evaluate(mock_azure, subscription_id)
    containers = _storage_id("sa-mixed") + "/blobServices/default/containers"
    assert _status(evaluations, f"{containers}/plain") == (EvaluationStatus.NOT_APPLICABLE, "POLICY_NOT_REQUIRED")
    assert _status(evaluations, f"{containers}/kept") == (EvaluationStatus.PASS, None)
    assert _status(evaluations, f"{containers}/open") == (EvaluationStatus.FAIL, None)
    assert _status(evaluations, f"{containers}/waived") == (EvaluationStatus.NOT_APPLICABLE, "APPROVED_EXCEPTION")
    assert _status(evaluations, _storage_id("sa-empty")) == (EvaluationStatus.NOT_APPLICABLE, "NO_RESOURCES_FOUND")
    assert _status(evaluations, _storage_id("sa-unlisted")) == (EvaluationStatus.UNKNOWN, "EVIDENCE_UNAVAILABLE")


def test_stor_010_public_access_disabled_and_unavailable_connections(mock_azure, subscription_id):
    mock_azure.set_storage_accounts(
        [
            make_resource(id=_storage_id("sa-closed"), name="sa-closed", public_network_access="Disabled"),
            make_resource(
                id=_storage_id("sa-unread"),
                name="sa-unread",
                public_network_access="Enabled",
                private_endpoint_connections=None,
            ),
            make_resource(
                id=_storage_id("sa-private"),
                name="sa-private",
                public_network_access="Enabled",
                private_endpoint_connections=[_private_endpoint("Approved")],
            ),
        ]
    )
    evaluations = az_stor_010.evaluate(mock_azure, subscription_id)
    assert _status(evaluations, _storage_id("sa-closed")) == (EvaluationStatus.NOT_APPLICABLE, "PUBLIC_ACCESS_DISABLED")
    assert _status(evaluations, _storage_id("sa-unread")) == (EvaluationStatus.UNKNOWN, "EVIDENCE_UNAVAILABLE")
    assert _status(evaluations, _storage_id("sa-private")) == (EvaluationStatus.PASS, None)


def test_storage_evaluations_record_the_checked_value_as_evidence(mock_azure, subscription_id):
    mock_azure.set_storage_accounts(
        [
            make_resource(
                id=_storage_id("sa-ev"),
                name="sa-ev",
                allow_blob_public_access=True,
                allow_shared_key_access=False,
                minimum_tls_version="TLS1_2",
            )
        ]
    )
    assert az_stor_001.evaluate(mock_azure, subscription_id)[0].evidence == {"allow_blob_public_access": True}
    assert az_stor_006.evaluate(mock_azure, subscription_id)[0].evidence == {"allow_shared_key_access": False}
    assert az_stor_007.evaluate(mock_azure, subscription_id)[0].evidence == {
        "minimum_tls_version": "TLS1_2",
        "normalized": "TLS1_2",
    }
