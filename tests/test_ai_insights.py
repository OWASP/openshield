"""Unit tests for POST /api/ai/insights."""

import json
import secrets
from unittest.mock import patch


def _fake_api_key() -> str:
    return secrets.token_urlsafe(24)


ENDPOINT = "/api/ai/insights"

MIXED_SEVERITY_FINDINGS = [
    {
        "rule_id": "AZ-NET-001",
        "severity": "MEDIUM",
        "title": "Network security group allows broad inbound access",
        "description": "Broad inbound access increases attack surface.",
        "remediation": "Restrict inbound rules to trusted IP ranges.",
    },
    {
        "rule_id": "AZ-IAM-001",
        "severity": "CRITICAL",
        "title": "Privileged identity lacks MFA",
        "description": "Admin identity can be compromised without MFA.",
        "remediation": "Enable MFA for privileged accounts.",
    },
    {
        "rule_id": "AZ-STOR-001",
        "severity": "HIGH",
        "title": "Storage account allows public blob access",
        "description": "Public access may expose sensitive data.",
        "remediation": "Disable public blob access.",
    },
    {
        "rule_id": "AZ-LOG-001",
        "severity": "LOW",
        "title": "Audit logs disabled",
        "description": "Audit visibility is reduced.",
        "remediation": "Enable diagnostic and audit logs.",
    },
]

VALID_PAYLOAD = {
    "provider": "groq",
    "api_key": _fake_api_key(),
    "findings": MIXED_SEVERITY_FINDINGS,
}


def _post(client, data, headers):
    return client.post(
        ENDPOINT,
        data=json.dumps(data),
        headers=headers,
    )


def test_missing_auth_returns_401(client):
    resp = client.post(
        ENDPOINT,
        data=json.dumps(VALID_PAYLOAD),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 401


def test_missing_json_body_returns_400(client, auth_headers):
    resp = client.post(ENDPOINT, headers=auth_headers)
    assert resp.status_code == 400


def test_missing_provider_returns_400(client, auth_headers):
    payload = {k: v for k, v in VALID_PAYLOAD.items() if k != "provider"}
    resp = _post(client, payload, auth_headers)
    assert resp.status_code == 400


def test_unsupported_provider_returns_400(client, auth_headers):
    payload = {**VALID_PAYLOAD, "provider": "openai"}
    resp = _post(client, payload, auth_headers)
    assert resp.status_code == 400


def test_missing_api_key_returns_400(client, auth_headers):
    payload = {k: v for k, v in VALID_PAYLOAD.items() if k != "api_key"}
    resp = _post(client, payload, auth_headers)
    assert resp.status_code == 400


def test_blank_api_key_returns_400(client, auth_headers):
    payload = {**VALID_PAYLOAD, "api_key": "   "}
    resp = _post(client, payload, auth_headers)
    assert resp.status_code == 400


def test_missing_findings_reads_scan_evidence_and_fails_closed_without_it(client, auth_headers, monkeypatch):
    """Without findings in the body, insights reads the latest completed scan
    (#357). When that evidence cannot be loaded it must fail closed, not answer
    from nothing."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    payload = {k: v for k, v in VALID_PAYLOAD.items() if k != "findings"}
    resp = _post(client, payload, auth_headers)
    assert resp.status_code == 503
    assert resp.get_json() == {"error": "Scan evidence is not available"}


def test_empty_findings_returns_400(client, auth_headers):
    payload = {**VALID_PAYLOAD, "findings": []}
    resp = _post(client, payload, auth_headers)
    assert resp.status_code == 400


def test_findings_must_be_list_returns_400(client, auth_headers):
    payload = {**VALID_PAYLOAD, "findings": {"rule_id": "X"}}
    resp = _post(client, payload, auth_headers)
    assert resp.status_code == 400


@patch("api.routes.ai.get_completion")
def test_valid_request_returns_expected_keys(mock_gc, client, auth_headers):
    mock_gc.side_effect = ["Mock executive summary.", "Mock remediation plan."]
    resp = _post(client, VALID_PAYLOAD, auth_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert "executive_summary" in body
    assert "remediation_plan" in body
    assert body["executive_summary"] == "Mock executive summary."
    assert body["remediation_plan"] == "Mock remediation plan."


@patch("api.routes.ai.get_completion")
def test_remediation_prompt_orders_findings_by_severity(mock_gc, client, auth_headers):
    mock_gc.side_effect = ["summary", "plan"]
    _post(client, VALID_PAYLOAD, auth_headers)

    assert mock_gc.call_count == 2
    remediation_prompt = mock_gc.call_args_list[1][0][2]

    critical_pos = remediation_prompt.index("CRITICAL")
    high_pos = remediation_prompt.index("HIGH")
    medium_pos = remediation_prompt.index("MEDIUM")
    low_pos = remediation_prompt.index("LOW")

    assert critical_pos < high_pos < medium_pos < low_pos


@patch("api.routes.ai.get_completion")
def test_anthropic_provider_supported(mock_gc, client, auth_headers):
    mock_gc.side_effect = ["summary", "plan"]
    payload = {**VALID_PAYLOAD, "provider": "anthropic"}
    resp = _post(client, payload, auth_headers)
    assert resp.status_code == 200


@patch("api.routes.ai.get_completion")
def test_groq_provider_supported(mock_gc, client, auth_headers):
    mock_gc.side_effect = ["summary", "plan"]
    payload = {**VALID_PAYLOAD, "provider": "groq"}
    resp = _post(client, payload, auth_headers)
    assert resp.status_code == 200


@patch("api.routes.ai.get_completion")
def test_gemini_provider_supported(mock_gc, client, auth_headers):
    mock_gc.side_effect = ["summary", "plan"]
    payload = {**VALID_PAYLOAD, "provider": "gemini"}
    resp = _post(client, payload, auth_headers)
    assert resp.status_code == 200


@patch("api.routes.ai.get_completion")
def test_no_question_omits_answer_field(mock_gc, client, auth_headers):
    mock_gc.side_effect = ["summary", "plan"]
    resp = _post(client, VALID_PAYLOAD, auth_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert "answer" not in body
    assert mock_gc.call_count == 2


@patch("api.routes.ai.get_completion")
def test_blank_question_treated_as_absent(mock_gc, client, auth_headers):
    mock_gc.side_effect = ["summary", "plan"]
    payload = {**VALID_PAYLOAD, "question": "   "}
    resp = _post(client, payload, auth_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert "answer" not in body
    assert mock_gc.call_count == 2


@patch("api.routes.ai.get_completion")
def test_question_returns_answer(mock_gc, client, auth_headers):
    mock_gc.side_effect = ["summary", "plan", "Fix the MFA finding first."]
    payload = {**VALID_PAYLOAD, "question": "Which findings should I fix first?"}
    resp = _post(client, payload, auth_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["executive_summary"] == "summary"
    assert body["remediation_plan"] == "plan"
    assert body["answer"] == "Fix the MFA finding first."
    assert mock_gc.call_count == 3


@patch("api.routes.ai.get_completion")
def test_question_prompt_includes_question_and_findings(mock_gc, client, auth_headers):
    mock_gc.side_effect = ["summary", "plan", "answer"]
    question = "What is the fastest path to CIS compliance?"
    payload = {**VALID_PAYLOAD, "question": question}
    _post(client, payload, auth_headers)

    question_prompt = mock_gc.call_args_list[2][0][2]
    assert question in question_prompt
    assert "AZ-IAM-001" in question_prompt


@patch("api.routes.ai.get_completion")
def test_question_answer_works_for_anthropic(mock_gc, client, auth_headers):
    mock_gc.side_effect = ["summary", "plan", "answer"]
    payload = {
        **VALID_PAYLOAD,
        "provider": "anthropic",
        "question": "Which finding is most exploitable?",
    }
    resp = _post(client, payload, auth_headers)
    assert resp.status_code == 200
    assert resp.get_json()["answer"] == "answer"


@patch("api.routes.ai.get_completion")
def test_question_answer_works_for_groq(mock_gc, client, auth_headers):
    mock_gc.side_effect = ["summary", "plan", "answer"]
    payload = {
        **VALID_PAYLOAD,
        "provider": "groq",
        "question": "Which finding is most exploitable?",
    }
    resp = _post(client, payload, auth_headers)
    assert resp.status_code == 200
    assert resp.get_json()["answer"] == "answer"


@patch("api.routes.ai.get_completion")
def test_question_answer_works_for_gemini(mock_gc, client, auth_headers):
    mock_gc.side_effect = ["summary", "plan", "answer"]
    payload = {
        **VALID_PAYLOAD,
        "provider": "gemini",
        "question": "Which finding is most exploitable?",
    }
    resp = _post(client, payload, auth_headers)
    assert resp.status_code == 200
    assert resp.get_json()["answer"] == "answer"


@patch("api.routes.ai.get_completion")
def test_question_provider_failure_returns_502(mock_gc, client, auth_headers, caplog):
    raw_key = _fake_api_key()
    payload = {
        **VALID_PAYLOAD,
        "api_key": raw_key,
        "question": "Which findings should I fix first?",
    }
    mock_gc.side_effect = ["summary", "plan", RuntimeError(f"auth failed: {raw_key}")]
    with caplog.at_level("WARNING", logger="api.routes.ai"):
        resp = _post(client, payload, auth_headers)
    assert resp.status_code == 502
    body_str = json.dumps(resp.get_json())
    assert "answer" not in resp.get_json()
    assert raw_key not in body_str
    assert raw_key not in caplog.text


@patch("api.routes.ai.get_completion")
def test_api_key_not_in_response_with_question(mock_gc, client, auth_headers):
    raw_key = _fake_api_key()
    mock_gc.side_effect = ["summary", "plan", "answer"]
    payload = {
        **VALID_PAYLOAD,
        "api_key": raw_key,
        "question": "Which findings should I fix first?",
    }
    resp = _post(client, payload, auth_headers)
    assert resp.status_code == 200
    assert raw_key not in json.dumps(resp.get_json())


@patch("api.routes.ai.get_completion")
def test_provider_failure_returns_502(mock_gc, client, auth_headers, caplog):
    raw_key = _fake_api_key()
    payload = {**VALID_PAYLOAD, "api_key": raw_key}
    mock_gc.side_effect = RuntimeError(f"auth failed: {raw_key}")
    with caplog.at_level("WARNING", logger="api.routes.ai"):
        resp = _post(client, payload, auth_headers)
    assert resp.status_code == 502
    body_str = json.dumps(resp.get_json())
    assert raw_key not in body_str
    assert raw_key not in caplog.text
