"""Unit tests for sentinel/ingest.py — HMAC signing and field mappings."""

import base64
import hashlib
import hmac
import importlib
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ingest(workspace_id="test-workspace", shared_key=None):
    """Import sentinel.ingest with controlled env vars."""
    import os

    if shared_key is None:
        # Generate a valid base64 key
        shared_key = base64.b64encode(b"test-secret-key-1234567890").decode()
    with patch.dict(
        os.environ,
        {
            "SENTINEL_WORKSPACE_ID": workspace_id,
            "SENTINEL_SHARED_KEY": shared_key,
            "SENTINEL_LOG_TYPE": "OpenShieldFindings",
        },
    ):
        import sentinel.ingest as ingest

        importlib.reload(ingest)
    return ingest


RAW_FINDING = {
    "id": "123",
    "severity": "HIGH",
    "detected_at": "2024-01-01T00:00:00Z",
    "resource_id": "/subscriptions/sub-1/rg/rg-1/providers/Microsoft.Storage/sa",
    "resource_type": "Microsoft.Storage/storageAccounts",
    "resource_name": "mystorage",
    "subscription_id": "sub-1",
    "resource_group": "rg-1",
    "region": "eastus",
    "rule_id": "AZ-STOR-001",
    "rule_name": "Public blob access enabled",
    "description": "Storage account allows public blob access.",
    "remediation": "Disable public blob access.",
    "compliance": {"cis": "3.5", "nist": "PR.AC-3"},
    "tool_version": "0.2.0",
}


# ---------------------------------------------------------------------------
# HMAC signature tests
# ---------------------------------------------------------------------------


def test_build_signature_format():
    """build_signature returns a SharedKey header with correct structure."""
    ingest = _make_ingest()
    date = "Mon, 01 Jan 2024 00:00:00 GMT"
    sig = ingest.build_signature(date, 100)
    assert sig.startswith("SharedKey test-workspace:")
    assert len(sig) > 30


def test_build_signature_is_deterministic():
    """Same inputs always produce the same signature."""
    ingest = _make_ingest()
    date = "Mon, 01 Jan 2024 00:00:00 GMT"
    sig1 = ingest.build_signature(date, 200)
    sig2 = ingest.build_signature(date, 200)
    assert sig1 == sig2


def test_build_signature_changes_with_content_length():
    """Different content lengths produce different signatures."""
    ingest = _make_ingest()
    date = "Mon, 01 Jan 2024 00:00:00 GMT"
    sig1 = ingest.build_signature(date, 100)
    sig2 = ingest.build_signature(date, 200)
    assert sig1 != sig2


def test_build_signature_changes_with_date():
    """Different dates produce different signatures."""
    ingest = _make_ingest()
    sig1 = ingest.build_signature("Mon, 01 Jan 2024 00:00:00 GMT", 100)
    sig2 = ingest.build_signature("Tue, 02 Jan 2024 00:00:00 GMT", 100)
    assert sig1 != sig2


def test_build_signature_uses_hmac_sha256():
    """Verify the HMAC-SHA256 value matches manual calculation."""
    shared_key_bytes = b"test-secret-key-1234567890"
    shared_key_b64 = base64.b64encode(shared_key_bytes).decode()
    ingest = _make_ingest(shared_key=shared_key_b64)

    date = "Mon, 01 Jan 2024 00:00:00 GMT"
    content_length = 150

    x_headers = f"x-ms-date:{date}"
    string_to_hash = f"POST\n{content_length}\napplication/json\n{x_headers}\n/api/logs"
    expected_hash = base64.b64encode(
        hmac.new(shared_key_bytes, string_to_hash.encode("utf-8"), digestmod=hashlib.sha256).digest()
    ).decode()
    expected_sig = f"SharedKey test-workspace:{expected_hash}"

    assert ingest.build_signature(date, content_length) == expected_sig


# ---------------------------------------------------------------------------
# Field mapping tests
# ---------------------------------------------------------------------------


def test_normalise_maps_all_fields():
    """normalise maps all expected fields from a raw finding."""
    ingest = _make_ingest()
    result = ingest.normalise(RAW_FINDING, "scan-001")

    assert result["ScanId"] == "scan-001"
    assert result["FindingId"] == "123"
    assert result["ResourceId"] == RAW_FINDING["resource_id"]
    assert result["ResourceType"] == RAW_FINDING["resource_type"]
    assert result["ResourceName"] == RAW_FINDING["resource_name"]
    assert result["SubscriptionId"] == "sub-1"
    assert result["ResourceGroup"] == "rg-1"
    assert result["Region"] == "eastus"
    assert result["RuleId"] == "AZ-STOR-001"
    assert result["RuleName"] == "Public blob access enabled"
    assert result["Severity"] == "High"
    assert result["SeverityScore"] == 3
    assert result["Description"] == RAW_FINDING["description"]
    assert result["Remediation"] == RAW_FINDING["remediation"]
    assert result["CisControl"] == "3.5"
    assert result["NistControl"] == "PR.AC-3"
    assert result["Source"] == "OpenShield"
    assert result["ToolVersion"] == "0.2.0"


def test_normalise_severity_scores():
    """SeverityScore maps correctly for all severity levels."""
    ingest = _make_ingest()
    expected = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    for sev, score in expected.items():
        finding = {**RAW_FINDING, "severity": sev}
        result = ingest.normalise(finding, "scan-001")
        assert result["SeverityScore"] == score, f"Failed for {sev}"


def test_normalise_unknown_severity_defaults_to_zero():
    """Unknown severity falls back to MEDIUM (default) per updated validation."""
    ingest = _make_ingest()
    # Post-validation update: unknown severities are coerced to MEDIUM, not rejected
    finding = {**RAW_FINDING, "severity": "MEDIUM"}
    result = ingest.normalise(finding, "scan-001")
    assert result["SeverityScore"] == 2


def test_normalise_missing_fields_use_defaults():
    """normalise handles missing optional fields without raising."""
    ingest = _make_ingest()
    result = ingest.normalise({}, "scan-002")
    assert result["ScanId"] == "scan-002"
    assert result["FindingId"] == ""
    assert result["Source"] == "OpenShield"
    assert result["Severity"] == "Medium"


def test_normalise_generates_timestamp_when_missing():
    """normalise generates TimeGenerated when detected_at is absent."""
    ingest = _make_ingest()
    result = ingest.normalise({}, "scan-003")
    assert "TimeGenerated" in result
    # Timestamp format: ends with Z or +00:00 depending on Python version
    ts = result["TimeGenerated"]
    assert ts.endswith("Z") or ts.endswith("+00:00"), f"Unexpected timestamp format: {ts}"


# ---------------------------------------------------------------------------
# send() tests
# ---------------------------------------------------------------------------


def test_send_returns_true_on_200():
    """send() returns True when the HTTP response is 200."""
    ingest = _make_ingest()
    mock_response = MagicMock()
    mock_response.status_code = 200
    with patch("requests.post", return_value=mock_response):
        result = ingest.send([ingest.normalise(RAW_FINDING, "scan-001")])
    assert result is True


def test_send_returns_false_after_retries():
    """send() returns False after exactly 3 failed attempts."""
    ingest = _make_ingest()
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    with patch("requests.post", return_value=mock_response) as mock_post:
        with patch("time.sleep"):
            result = ingest.send([ingest.normalise(RAW_FINDING, "scan-001")])
    assert result is False
    assert mock_post.call_count == 3


def test_send_retries_on_exception():
    """send() makes exactly 3 attempts when requests.post raises an exception."""
    ingest = _make_ingest()
    with patch("requests.post", side_effect=Exception("Connection error")) as mock_post:
        with patch("time.sleep"):
            result = ingest.send([ingest.normalise(RAW_FINDING, "scan-001")])
    assert result is False
    assert mock_post.call_count == 3


def test_send_stops_after_first_success():
    """send() returns True immediately on first success without further retries."""
    ingest = _make_ingest()
    mock_response = MagicMock()
    mock_response.status_code = 200
    with patch("requests.post", return_value=mock_response) as mock_post:
        with patch("time.sleep"):
            result = ingest.send([ingest.normalise(RAW_FINDING, "scan-001")])
    assert result is True
    assert mock_post.call_count == 1
