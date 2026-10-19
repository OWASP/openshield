"""Integration tests for POST /api/agent/query."""

from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_GOOD_RESULT = {
    "answer": "You have 3 critical findings.",
    "tools_used": ["get_findings"],
    "iterations": 2,
    "confidence": "HIGH",
}


def _mock_db():
    db = MagicMock()
    db.conn = MagicMock()
    return db


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAgentQueryRoute:
    """Tests for POST /api/agent/query."""

    def _post(self, client, auth_headers, body, env=None):
        env = env or {}
        with patch.dict("os.environ", {"AI_API_KEY": "test-key", **env}):
            return client.post("/api/agent/query", json=body, headers=auth_headers)

    # 1. Valid request returns 200 with all expected fields
    def test_valid_request_returns_200(self, client, auth_headers):
        with patch("api.routes.agent.run_agent", return_value=_GOOD_RESULT) as mock_run, \
             patch("api.routes.agent._get_db", return_value=_mock_db()):
            resp = self._post(client, auth_headers, {"question": "What are my critical findings?", "subscription_id": "sub-001"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["answer"] == _GOOD_RESULT["answer"]
        assert data["tools_used"] == _GOOD_RESULT["tools_used"]
        assert data["iterations"] == _GOOD_RESULT["iterations"]
        assert data["confidence"] == _GOOD_RESULT["confidence"]

    # 2. Missing question field returns 400
    def test_missing_question_returns_400(self, client, auth_headers):
        with patch.dict("os.environ", {"AI_API_KEY": "test-key"}):
            resp = client.post("/api/agent/query", json={"framework": "mcsb"}, headers=auth_headers)
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "question is required"

    # 3. Empty string question returns 400
    def test_empty_question_returns_400(self, client, auth_headers):
        with patch.dict("os.environ", {"AI_API_KEY": "test-key"}):
            resp = client.post("/api/agent/query", json={"question": "   "}, headers=auth_headers)
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "question is required"

    # 4. Missing AI_API_KEY returns 503
    def test_missing_api_key_returns_503(self, client, auth_headers):
        with patch.dict("os.environ", {}, clear=True):
            # Ensure AI_API_KEY is absent
            import os
            env_backup = os.environ.pop("AI_API_KEY", None)
            try:
                resp = client.post(
                    "/api/agent/query",
                    json={"question": "What are my findings?"},
                    headers=auth_headers,
                )
            finally:
                if env_backup is not None:
                    os.environ["AI_API_KEY"] = env_backup
        assert resp.status_code == 503
        assert resp.get_json()["error"] == "AI provider not configured"

    # 5. run_agent raises unexpected exception -> 500
    def test_run_agent_exception_returns_500(self, client, auth_headers):
        with patch("api.routes.agent.run_agent", side_effect=RuntimeError("boom")), \
             patch("api.routes.agent._get_db", return_value=_mock_db()), \
             patch.dict("os.environ", {"AI_API_KEY": "test-key"}):
            resp = client.post(
                "/api/agent/query",
                json={"question": "What are my findings?", "subscription_id": "sub-001"},
                headers=auth_headers,
            )
        assert resp.status_code == 500
        assert resp.get_json()["error"] == "internal server error"

    # 6. Rate limit: 21st request returns 429
    def test_rate_limit_blocks_excess_requests(self, client, auth_headers):
        """21st request within the window must return 429."""
        with patch("api.routes.agent.run_agent", return_value=_GOOD_RESULT), \
             patch("api.routes.agent._get_db", return_value=_mock_db()), \
             patch.dict("os.environ", {"AI_API_KEY": "test-key", "DATABASE_URL": "postgresql://test"}):

            # Patch _check_and_record directly: first 20 return True, then False
            call_count = {"n": 0}

            def fake_check_and_record(key, max_requests, window_seconds):
                call_count["n"] += 1
                return call_count["n"] <= max_requests

            with patch("api.rate_limit._check_and_record", side_effect=fake_check_and_record):
                # Make app non-testing so rate limiter runs
                client.application.config["TESTING"] = False
                try:
                    for _ in range(20):
                        r = client.post(
                            "/api/agent/query",
                            json={"question": "test", "subscription_id": "sub-001"},
                            headers=auth_headers,
                        )
                        assert r.status_code == 200
                    r21 = client.post(
                        "/api/agent/query",
                        json={"question": "test", "subscription_id": "sub-001"},
                        headers=auth_headers,
                    )
                    assert r21.status_code == 429
                finally:
                    client.application.config["TESTING"] = True

    # 7. tenant_id comes from JWT (g.user), not from request body
    def test_tenant_from_jwt_not_body(self, client, auth_headers):
        """Verify run_agent receives tenant_id from g.user, never from request body."""
        captured = {}

        def fake_run_agent(**kwargs):
            captured.update(kwargs)
            return _GOOD_RESULT

        with patch("api.routes.agent.run_agent", side_effect=fake_run_agent), \
             patch("api.routes.agent._get_db", return_value=_mock_db()), \
             patch.dict("os.environ", {"AI_API_KEY": "test-key"}):
            resp = client.post(
                "/api/agent/query",
                json={
                    "question": "What are my findings?",
                    "subscription_id": "sub-001",
                    "tenant_id": "attacker-tenant",
                },
                headers=auth_headers,
            )
        assert resp.status_code == 200
        # tenant_id must NOT be the attacker-supplied value from the request body
        assert captured.get("tenant_id") != "attacker-tenant"
        # tenant_id is a string (from g.user["tenant"], empty string in test JWT)
        assert isinstance(captured.get("tenant_id"), str)
