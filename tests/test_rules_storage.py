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
