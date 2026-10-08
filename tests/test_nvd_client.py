"""
tests/test_nvd_client.py

Unit tests for scanner/nvd_client.py.

All NVD HTTP calls are mocked - no real network requests are made.
The module-level cache is cleared in setUp() so tests do not interfere
with each other.

Test classes:
  TestParseConveItem  - _parse_cve_item() logic (no mocking needed)
  TestQueryNvd        - query_nvd() HTTP behaviour (mocked urlopen)
"""

import threading
import time
import unittest
from unittest.mock import patch, MagicMock

import requests

# Clear the module cache before import so previous test runs don't bleed in
from scanner.nvd_client import query_nvd, _parse_cve_item, _cache, _wait_for_rate_limit


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------

_SAMPLE_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2023-12345",
                "descriptions": [{"lang": "en", "value": "A critical vulnerability in Azure Storage."}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
                "cisaExploitAdd": "2023-06-01",
            }
        },
        {
            "cve": {
                "id": "CVE-2022-99999",
                "descriptions": [{"lang": "en", "value": "Medium severity configuration issue."}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 5.4,
                                "baseSeverity": "MEDIUM",
                            }
                        }
                    ]
                },
            }
        },
    ]
}

_EMPTY_NVD_RESPONSE = {"vulnerabilities": []}


def _make_mock_requests_response(data: dict, status: int = 200) -> MagicMock:
    """
    Return a MagicMock that behaves like a requests NVD response.

    `raise_for_status()` raises the same requests exception the client handles.
    """
    mock_resp = MagicMock()
    mock_resp.json.return_value = data
    mock_resp.status_code = status
    if status >= 400:
        mock_resp.raise_for_status.side_effect = requests.HTTPError(response=mock_resp)
    return mock_resp


# ---------------------------------------------------------------------------
# TestParseConveItem
# Tests for _parse_cve_item() - pure function, no mocking needed.
# ---------------------------------------------------------------------------


class TestParseConveItem(unittest.TestCase):
    """
    _parse_cve_item() receives one item from the NVD "vulnerabilities" array
    and returns a flat dict with the fields OpenShield needs, or None if the
    item is malformed.
    """

    def test_parses_cve_id(self):
        """The cve_id field is extracted correctly."""
        item = _SAMPLE_NVD_RESPONSE["vulnerabilities"][0]
        result = _parse_cve_item(item)
        self.assertEqual(result["cve_id"], "CVE-2023-12345")

    def test_parses_cvss_v31_score(self):
        """CVSS v3.1 baseScore is used when available."""
        item = _SAMPLE_NVD_RESPONSE["vulnerabilities"][0]
        result = _parse_cve_item(item)
        self.assertEqual(result["cvss_score"], 9.8)
        self.assertEqual(result["cvss_severity"], "CRITICAL")

    def test_exploit_available_when_cisa_key_present(self):
        """exploit_available is True when cisaExploitAdd key exists in NVD data."""
        item = _SAMPLE_NVD_RESPONSE["vulnerabilities"][0]
        result = _parse_cve_item(item)
        self.assertTrue(result["exploit_available"])

    def test_exploit_not_available_when_cisa_key_absent(self):
        """exploit_available is False when cisaExploitAdd key is absent."""
        item = _SAMPLE_NVD_RESPONSE["vulnerabilities"][1]
        result = _parse_cve_item(item)
        self.assertFalse(result["exploit_available"])

    def test_returns_none_for_empty_item(self):
        """Malformed items with no cve.id return None instead of raising."""
        result = _parse_cve_item({})
        self.assertIsNone(result)

    def test_description_truncated_at_300_chars(self):
        """Descriptions longer than 300 characters are truncated for DB storage."""
        item = {
            "cve": {
                "id": "CVE-2024-00001",
                "descriptions": [{"lang": "en", "value": "x" * 500}],
                "metrics": {},
            }
        }
        result = _parse_cve_item(item)
        self.assertIsNotNone(result)
        self.assertLessEqual(len(result["description"]), 300)

    def test_nvd_url_format(self):
        """nvd_url points to the correct NVD detail page for the CVE."""
        item = _SAMPLE_NVD_RESPONSE["vulnerabilities"][0]
        result = _parse_cve_item(item)
        self.assertEqual(
            result["nvd_url"],
            "https://nvd.nist.gov/vuln/detail/CVE-2023-12345",
        )

    def test_falls_back_to_cvss_v2_when_v31_absent(self):
        """When cvssMetricV31 is absent, falls back to cvssMetricV2."""
        item = {
            "cve": {
                "id": "CVE-2010-00001",
                "descriptions": [{"lang": "en", "value": "Old CVE."}],
                "metrics": {
                    "cvssMetricV2": [
                        {
                            "cvssData": {
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                            }
                        }
                    ]
                },
            }
        }
        result = _parse_cve_item(item)
        self.assertEqual(result["cvss_score"], 7.5)


# ---------------------------------------------------------------------------
# TestQueryNvd
# Tests for query_nvd() - mocks requests.get to prevent live calls.
# Also mocks _wait_for_rate_limit to keep tests fast.
# ---------------------------------------------------------------------------


class TestQueryNvd(unittest.TestCase):
    """
    query_nvd() uses the fixed NVD HTTPS URL, parses the response, caches it,
    and handles errors gracefully. All HTTP is mocked.
    """

    def setUp(self):
        """Clear the module-level cache before each test."""
        _cache.clear()

    @patch("scanner.nvd_client.requests.get")
    @patch("scanner.nvd_client._wait_for_rate_limit")
    def test_returns_parsed_cves_on_success(self, mock_wait, mock_get):
        """Successful response is parsed into a list of CVE dicts."""
        mock_get.return_value = _make_mock_requests_response(_SAMPLE_NVD_RESPONSE)
        results = query_nvd("Azure Storage Account")
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["cve_id"], "CVE-2023-12345")
        self.assertEqual(results[1]["cve_id"], "CVE-2022-99999")
        mock_get.assert_called_once_with(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": "Azure Storage Account", "startIndex": 0, "resultsPerPage": 2000},
            headers={"User-Agent": "OpenShield/0.1 (github.com/openshield-org/openshield)"},
            timeout=10,
        )

    @patch("scanner.nvd_client.requests.get")
    @patch("scanner.nvd_client._wait_for_rate_limit")
    def test_returns_empty_list_on_empty_nvd_response(self, mock_wait, mock_get):
        """An empty vulnerabilities list returns [] without error."""
        mock_get.return_value = _make_mock_requests_response(_EMPTY_NVD_RESPONSE)
        results = query_nvd("nonexistent-resource-xyz")
        self.assertEqual(results, [])

    @patch("scanner.nvd_client.requests.get")
    @patch("scanner.nvd_client._wait_for_rate_limit")
    def test_second_call_uses_cache(self, mock_wait, mock_get):
        """
        Calling query_nvd twice with the same keyword only makes one request.
        The second call must return from cache without a network request.
        """
        mock_get.return_value = _make_mock_requests_response(_SAMPLE_NVD_RESPONSE)
        query_nvd("Azure Storage Account")
        query_nvd("Azure Storage Account")  # Should be served from cache
        self.assertEqual(mock_get.call_count, 1)

    @patch("scanner.nvd_client.requests.get")
    @patch("scanner.nvd_client._wait_for_rate_limit")
    def test_fetches_every_nvd_page(self, mock_wait, mock_get):
        first_page = {"totalResults": 2, "vulnerabilities": [_SAMPLE_NVD_RESPONSE["vulnerabilities"][0]]}
        second_page = {"totalResults": 2, "vulnerabilities": [_SAMPLE_NVD_RESPONSE["vulnerabilities"][1]]}
        mock_get.side_effect = [
            _make_mock_requests_response(first_page),
            _make_mock_requests_response(second_page),
        ]

        results = query_nvd("Azure Storage Account", results_per_page=1)

        self.assertEqual([item["cve_id"] for item in results], ["CVE-2023-12345", "CVE-2022-99999"])
        self.assertEqual(mock_get.call_count, 2)

    @patch("scanner.nvd_client.requests.get")
    @patch("scanner.nvd_client._wait_for_rate_limit")
    def test_returns_empty_list_on_network_error(self, mock_wait, mock_get):
        """A network exception returns [] and does not propagate the error."""
        mock_get.side_effect = requests.ConnectionError("Connection refused")
        results = query_nvd("Azure Storage Account")
        self.assertEqual(results, [])

    @patch("scanner.nvd_client.requests.get")
    @patch("scanner.nvd_client._wait_for_rate_limit")
    def test_returns_empty_list_on_http_503(self, mock_wait, mock_get):
        """An HTTP 503 returns [] and does not propagate the error."""
        mock_get.return_value = _make_mock_requests_response({}, status=503)
        results = query_nvd("Azure Storage Account")
        self.assertEqual(results, [])

    @patch("scanner.nvd_client.time.sleep")
    @patch("scanner.nvd_client.requests.get")
    @patch("scanner.nvd_client._wait_for_rate_limit")
    def test_backs_off_and_retries_on_429(self, mock_wait, mock_get, mock_sleep):
        """
        A 429 response triggers a sleep and retry.
        After MAX_RETRIES 429s, returns [] gracefully.
        """
        mock_get.return_value = _make_mock_requests_response({}, status=429)
        results = query_nvd("Azure Storage Account")
        self.assertEqual(results, [])
        # time.sleep should have been called (back-off logic)
        self.assertTrue(mock_sleep.called)


# ---------------------------------------------------------------------------
# TestRateLimitThreadSafety
# REL-005: _wait_for_rate_limit must serialize concurrent callers so two
# threads can't both read a stale _last_request_time and fire requests
# closer together than _REQUEST_DELAY_SECONDS apart.
# ---------------------------------------------------------------------------


class TestRateLimitThreadSafety(unittest.TestCase):
    def setUp(self):
        patcher = patch("scanner.nvd_client._rate_limiter._last_request_time", 0.0)
        patcher.start()
        self.addCleanup(patcher.stop)

    @patch("scanner.nvd_client._REQUEST_DELAY_SECONDS", 0.05)
    def test_concurrent_calls_are_serialized_not_interleaved(self):
        timestamps = []
        record_lock = threading.Lock()

        def call():
            _wait_for_rate_limit()
            with record_lock:
                timestamps.append(time.monotonic())

        threads = [threading.Thread(target=call) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        timestamps.sort()
        gaps = [b - a for a, b in zip(timestamps, timestamps[1:])]
        # Each recorded call must be spaced by roughly the delay; a broken
        # (unlocked) guard lets threads read the same stale timestamp and
        # return almost simultaneously, producing near-zero gaps.
        for gap in gaps:
            self.assertGreaterEqual(gap, 0.04)


if __name__ == "__main__":
    unittest.main()
