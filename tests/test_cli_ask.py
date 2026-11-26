"""Tests for the `openshield ask` CLI command."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_GOOD_RESPONSE = {
    "answer": "You have 3 critical findings.",
    "tools_used": ["get_findings", "explain_finding"],
    "iterations": 2,
    "confidence": "HIGH",
}


def _mock_response(status_code: int, json_body: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body
    resp.text = str(json_body)
    return resp


def _run_cli(*args: str, env: dict | None = None) -> tuple[int, str, str]:
    """Run the CLI with the given argv and return (exit_code, stdout, stderr)."""
    import io
    from cli import main

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()

    with patch("sys.stdout", stdout_buf), patch("sys.stderr", stderr_buf):
        exit_code = main(list(args))

    return exit_code, stdout_buf.getvalue(), stderr_buf.getvalue()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAskCommand:
    """Tests for `openshield ask`."""

    def test_successful_response_prints_answer_and_metadata(self):
        """A 200 response prints the answer then a metadata line."""
        mock_resp = _mock_response(200, _GOOD_RESPONSE)

        with (
            patch("requests.post", return_value=mock_resp) as mock_post,
            patch.dict("os.environ", {"OPENSHIELD_TOKEN": "test-token"}, clear=False),
        ):
            exit_code, stdout, stderr = _run_cli(
                "ask",
                "What are my critical findings?",
                "--subscription",
                "sub-001",
            )

        assert exit_code == 0
        assert "You have 3 critical findings." in stdout
        assert "[tools used:" in stdout
        assert "get_findings" in stdout
        assert "confidence: HIGH" in stdout
        assert "iterations: 2" in stdout
        # No live HTTP call — mock was used
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert "/api/agent/query" in call_kwargs[0][0]
        body = call_kwargs[1]["json"]
        assert body["question"] == "What are my critical findings?"
        assert body["subscription_id"] == "sub-001"

    def test_api_error_prints_error_and_exits_1(self):
        """A 4xx response prints the error field and exits with code 1."""
        mock_resp = _mock_response(403, {"error": "Subscription not authorized"})

        with (
            patch("requests.post", return_value=mock_resp),
            patch.dict("os.environ", {"OPENSHIELD_TOKEN": "test-token"}, clear=False),
        ):
            exit_code, stdout, stderr = _run_cli(
                "ask",
                "What are my critical findings?",
                "--subscription",
                "sub-001",
            )

        assert exit_code == 1
        assert "Subscription not authorized" in stderr

    def test_missing_subscription_exits_before_http_call(self):
        """When subscription is absent (no arg, no env var), exit 1 without HTTP."""
        # Ensure AZURE_SUBSCRIPTION_ID is not set
        with patch("requests.post") as mock_post, patch.dict("os.environ", {}, clear=True):
            # Also clear OPENSHIELD_TOKEN to isolate; provide token via arg
            exit_code, stdout, stderr = _run_cli(
                "ask",
                "What are my critical findings?",
                "--token",
                "test-token",
            )

        assert exit_code == 1
        assert "subscription" in stderr.lower()
        mock_post.assert_not_called()

    def test_missing_token_exits_before_http_call(self):
        """When token is absent (no arg, no env var), exit 1 without HTTP."""
        with patch("requests.post") as mock_post, patch.dict("os.environ", {}, clear=True):
            exit_code, stdout, stderr = _run_cli(
                "ask",
                "What are my critical findings?",
                "--subscription",
                "sub-001",
            )

        assert exit_code == 1
        assert "token" in stderr.lower()
        mock_post.assert_not_called()

    def test_connection_error_exits_1_with_friendly_message(self):
        """A connection error prints a friendly message and exits with code 1."""
        import requests as req_lib

        with (
            patch("requests.post", side_effect=req_lib.ConnectionError("refused")),
            patch.dict("os.environ", {"OPENSHIELD_TOKEN": "test-token"}, clear=False),
        ):
            exit_code, stdout, stderr = _run_cli(
                "ask",
                "What are my critical findings?",
                "--subscription",
                "sub-001",
            )

        assert exit_code == 1
        assert "connect" in stderr.lower()

    def test_framework_flag_included_in_request_body(self):
        """When --framework is supplied, it is sent in the request body."""
        mock_resp = _mock_response(200, {**_GOOD_RESPONSE})

        with (
            patch("requests.post", return_value=mock_resp) as mock_post,
            patch.dict("os.environ", {"OPENSHIELD_TOKEN": "test-token"}, clear=False),
        ):
            exit_code, stdout, stderr = _run_cli(
                "ask",
                "What is my MCSB compliance score?",
                "--subscription",
                "sub-001",
                "--framework",
                "mcsb",
            )

        assert exit_code == 0
        body = mock_post.call_args[1]["json"]
        assert body.get("framework") == "mcsb"
