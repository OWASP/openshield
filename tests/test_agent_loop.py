"""Unit tests for api.agent.agent â€” the ReAct loop.

All LLM calls are mocked; no live network calls are made.
"""

import json
import unittest
from unittest.mock import MagicMock, patch

from api.agent.agent import run_agent


_PROVIDER = "anthropic"
_API_KEY = "test-key"
_SUB_ID = "sub-123"
_TENANT_ID = "tenant-abc"

# Minimal fake db_conn so tool dispatch does not raise AttributeError
def _fake_db():
    return MagicMock()


def _answer(text: str, confidence: str = "HIGH") -> str:
    return json.dumps({"answer": text, "confidence": confidence})


def _tool_call(name: str, args: dict = None) -> str:
    return json.dumps({"tool": name, "args": args or {}})


class TestSingleTurnAnswer(unittest.TestCase):
    """LLM returns a final answer on the first call."""

    @patch("api.agent.agent.get_completion")
    def test_returns_answer_immediately(self, mock_llm):
        mock_llm.return_value = _answer("Everything looks good.", "HIGH")

        result = run_agent(
            question="Are there any critical findings?",
            subscription_id=_SUB_ID,
            tenant_id=_TENANT_ID,
            db_conn=_fake_db(),
            provider=_PROVIDER,
            api_key=_API_KEY,
        )

        self.assertEqual(result["answer"], "Everything looks good.")
        self.assertEqual(result["confidence"], "HIGH")
        self.assertEqual(result["iterations"], 1)
        self.assertEqual(result["tools_used"], [])
        mock_llm.assert_called_once()


class TestToolCallThenAnswer(unittest.TestCase):
    """LLM calls a tool first, then gives a final answer."""

    @patch("api.agent.tools.get_findings", return_value=[{"finding_id": 1, "severity": "HIGH"}])
    @patch("api.agent.agent.get_completion")
    def test_tool_then_answer(self, mock_llm, mock_get_findings):
        mock_llm.side_effect = [
            _tool_call("get_findings", {"severity": "HIGH"}),
            _answer("Found 1 HIGH finding.", "HIGH"),
        ]

        result = run_agent(
            question="Show me HIGH findings",
            subscription_id=_SUB_ID,
            tenant_id=_TENANT_ID,
            db_conn=_fake_db(),
            provider=_PROVIDER,
            api_key=_API_KEY,
        )

        self.assertEqual(result["answer"], "Found 1 HIGH finding.")
        self.assertEqual(result["iterations"], 2)
        self.assertIn("get_findings", result["tools_used"])
        self.assertEqual(mock_llm.call_count, 2)


class TestMaxIterationsReached(unittest.TestCase):
    """LLM keeps calling tools; loop hits max_iterations and returns fallback."""

    @patch("api.agent.tools.get_findings", return_value=[])
    @patch("api.agent.agent.get_completion")
    def test_max_iterations_fallback(self, mock_llm, _mock_findings):
        mock_llm.return_value = _tool_call("get_findings")

        result = run_agent(
            question="List findings",
            subscription_id=_SUB_ID,
            tenant_id=_TENANT_ID,
            db_conn=_fake_db(),
            provider=_PROVIDER,
            api_key=_API_KEY,
            max_iterations=8,
        )

        self.assertIn("unable to gather", result["answer"].lower())
        self.assertEqual(result["confidence"], "LOW")
        self.assertEqual(result["iterations"], 8)
        self.assertEqual(mock_llm.call_count, 8)


class TestEmptyQuestionRaisesValueError(unittest.TestCase):
    """Empty question (after cleaning) raises ValueError."""

    @patch("api.agent.agent.get_completion")
    def test_empty_string_raises(self, mock_llm):
        with self.assertRaises(ValueError) as ctx:
            run_agent(
                question="   ",
                subscription_id=_SUB_ID,
                tenant_id=_TENANT_ID,
                db_conn=_fake_db(),
                provider=_PROVIDER,
                api_key=_API_KEY,
            )
        self.assertIn("required", str(ctx.exception).lower())
        mock_llm.assert_not_called()

    @patch("api.agent.agent.get_completion")
    def test_empty_string_literal_raises(self, mock_llm):
        with self.assertRaises(ValueError):
            run_agent(
                question="",
                subscription_id=_SUB_ID,
                tenant_id=_TENANT_ID,
                db_conn=_fake_db(),
                provider=_PROVIDER,
                api_key=_API_KEY,
            )
        mock_llm.assert_not_called()


class TestUnknownToolReturnsErrorAndContinues(unittest.TestCase):
    """Unknown tool name returns error dict; loop continues to next iteration."""

    @patch("api.agent.agent.get_completion")
    def test_unknown_tool_error_dict(self, mock_llm):
        mock_llm.side_effect = [
            _tool_call("nonexistent_tool"),
            _answer("Fallback answer after unknown tool.", "LOW"),
        ]

        result = run_agent(
            question="Do something",
            subscription_id=_SUB_ID,
            tenant_id=_TENANT_ID,
            db_conn=_fake_db(),
            provider=_PROVIDER,
            api_key=_API_KEY,
        )

        # Loop should have continued and returned the second response
        self.assertEqual(result["answer"], "Fallback answer after unknown tool.")
        self.assertEqual(result["iterations"], 2)
        # The bad tool name is still recorded in tools_used
        self.assertIn("nonexistent_tool", result["tools_used"])


class TestToolExceptionCaughtAndLoopContinues(unittest.TestCase):
    """Tool exception is caught and returned as error dict; loop does not crash."""

    @patch("api.agent.tools.get_findings", side_effect=RuntimeError("DB unavailable"))
    @patch("api.agent.agent.get_completion")
    def test_tool_exception_caught(self, mock_llm, _mock_findings):
        mock_llm.side_effect = [
            _tool_call("get_findings"),
            _answer("Could not retrieve findings.", "LOW"),
        ]

        result = run_agent(
            question="Get findings",
            subscription_id=_SUB_ID,
            tenant_id=_TENANT_ID,
            db_conn=_fake_db(),
            provider=_PROVIDER,
            api_key=_API_KEY,
        )

        # Loop must not raise; should reach the second LLM response
        self.assertEqual(result["answer"], "Could not retrieve findings.")
        self.assertEqual(result["iterations"], 2)


class TestUnparseableLLMResponse(unittest.TestCase):
    """Non-JSON LLM response is treated as a low-confidence final answer."""

    @patch("api.agent.agent.get_completion")
    def test_unparseable_is_low_confidence_answer(self, mock_llm):
        mock_llm.return_value = "This is just plain text, not JSON."

        result = run_agent(
            question="What is the posture?",
            subscription_id=_SUB_ID,
            tenant_id=_TENANT_ID,
            db_conn=_fake_db(),
            provider=_PROVIDER,
            api_key=_API_KEY,
        )

        self.assertIn("plain text", result["answer"])
        self.assertEqual(result["confidence"], "LOW")
        self.assertEqual(result["iterations"], 1)
        mock_llm.assert_called_once()


class TestToolsUsedOrder(unittest.TestCase):
    """tools_used records tool names in the order they were called."""

    @patch("api.agent.tools.get_findings", return_value=[])
    @patch("api.agent.tools.get_compliance_posture", return_value={"score": 0.9, "framework": "mcsb"})
    @patch("api.agent.agent.get_completion")
    def test_tools_used_in_order(self, mock_llm, _mock_posture, _mock_findings):
        mock_llm.side_effect = [
            _tool_call("get_findings"),
            _tool_call("get_compliance_posture", {"framework": "mcsb"}),
            _answer("Both tools called.", "HIGH"),
        ]

        result = run_agent(
            question="Show findings and posture",
            subscription_id=_SUB_ID,
            tenant_id=_TENANT_ID,
            db_conn=_fake_db(),
            provider=_PROVIDER,
            api_key=_API_KEY,
        )

        self.assertEqual(result["tools_used"], ["get_findings", "get_compliance_posture"])
        self.assertEqual(result["iterations"], 3)


if __name__ == "__main__":
    unittest.main()
