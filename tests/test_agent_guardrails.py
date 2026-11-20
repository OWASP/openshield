"""Tests for the backend-independent CSPM agent guardrails."""

from api.agent import guardrails as g


def test_validate_confidence_only_high_or_low():
    assert g.validate_confidence("HIGH") == "HIGH"
    assert g.validate_confidence("LOW") == "LOW"
    assert g.validate_confidence("TOTALLY") == "LOW"
    assert g.validate_confidence(None) == "LOW"
    assert g.validate_confidence(7) == "LOW"
    assert g.validate_confidence("high") == "LOW"  # case-sensitive by design


def test_wrap_untrusted_labels_and_is_string():
    out = g.wrap_untrusted("get_findings", [{"finding_id": 1}])
    assert isinstance(out, str)
    assert "UNTRUSTED" in out.upper()
    assert "get_findings" in out
    assert "finding_id" in out


def test_wrap_untrusted_handles_unserializable():
    class Weird:
        def __repr__(self):
            return "<weird>"

    out = g.wrap_untrusted("explain_finding", {"obj": Weird()})
    assert isinstance(out, str)
    assert "explain_finding" in out


def test_can_call_gates_writes_by_role():
    assert g.can_call("get_findings", "viewer") is True
    assert g.can_call("scan_subscription", "viewer") is False
    assert g.can_call("scan_subscription", "operator") is True
    assert g.can_call("scan_subscription", "admin") is True
    # Unknown / missing role is treated as unprivileged.
    assert g.can_call("scan_subscription", "") is False
    assert g.can_call("scan_subscription", None) is False


def test_write_tools_membership():
    assert "scan_subscription" in g.WRITE_TOOLS
    assert "get_findings" not in g.WRITE_TOOLS
