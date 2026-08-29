"""
scanner/nvd_client.py

MITRE NVD API client for OpenShield.

NVD public API: https://services.nvd.nist.gov/rest/json/cves/2.0
No API key required for basic use.
Rate limit (unauthenticated): 5 requests per 30 seconds.

Design decisions:
- In-memory cache keyed by search keyword to avoid duplicate NVD calls
  for the same resource type within one scan run.
- Enforces a 7-second gap between requests to stay under the rate limit.
- Retries on 429 (rate limited) with escalating back-off.
- All exceptions are caught here. Callers always receive a list - empty
  on failure - and never see an exception from this module.
"""

import threading
import time
import logging
import urllib.request
import urllib.error
import urllib.parse
import json
from typing import Optional

from api.observability import NVD_REQUEST_LATENCY_SECONDS

logger = logging.getLogger(__name__)

_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_REQUEST_DELAY_SECONDS = 7.0  # Stay under 5 req/30 sec limit
_MAX_RETRIES = 3
_RESULTS_PER_PAGE = 2000  # NVD's documented maximum; fetch every matching page.

# In-memory cache. Keyed by "keyword:results_per_page".
# Resets each process - intentional, NVD data changes slowly.
_cache: dict[str, list[dict]] = {}


class NvdRequestError(RuntimeError):
    """Raised by the durable worker when an NVD page cannot be retrieved."""


class _RateLimiter:
    """Tracks the last NVD request time, guarded by a lock so concurrent
    callers (e.g. background enrichment threads) can't both read a stale
    timestamp and fire requests closer together than _REQUEST_DELAY_SECONDS
    apart."""

    def __init__(self) -> None:
        self._last_request_time = 0.0
        self._lock = threading.Lock()

    def wait(self, delay_seconds: float) -> None:
        with self._lock:
            elapsed = time.time() - self._last_request_time
            if elapsed < delay_seconds:
                time.sleep(delay_seconds - elapsed)
            self._last_request_time = time.time()


_rate_limiter = _RateLimiter()


def _wait_for_rate_limit() -> None:
    """Sleep until the minimum gap between NVD requests has elapsed."""
    _rate_limiter.wait(_REQUEST_DELAY_SECONDS)


def _parse_cve_item(item: dict) -> Optional[dict]:
    """
    Extract the fields OpenShield needs from one NVD CVE item.

    NVD v2.0 response structure:
    {
      "cve": {
        "id": "CVE-2023-XXXXX",
        "descriptions": [{"lang": "en", "value": "..."}],
        "metrics": {
          "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
          "cvssMetricV30": [...],   # fallback if V31 absent
          "cvssMetricV2":  [...]    # older CVEs only
        },
        "cisaExploitAdd": "2023-01-01"  # present only if in CISA KEV catalogue
      }
    }

    Returns None if the item is malformed.
    """
    try:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        # Prefer English description
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available",
        )

        # CVSS score: try v3.1, then v3.0, then v2
        metrics = cve.get("metrics", {})
        cvss_score: Optional[float] = None
        cvss_severity: Optional[str] = None

        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity")
                break

        # exploit_available: True if the CVE is in CISA's Known Exploited
        # Vulnerabilities catalogue (more reliable than vendor-reported status)
        exploit_available = "cisaExploitAdd" in cve

        return {
            "cve_id": cve_id,
            "description": description[:300],  # Truncate for DB storage
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "exploit_available": exploit_available,
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }
    except Exception as e:
        logger.warning("Failed to parse CVE item: %s", e)
        return None


def _fetch_nvd_page(keyword: str, start_index: int, results_per_page: int) -> dict:
    """Fetch one NVD page, raising only after bounded retries are exhausted."""
    params = urllib.parse.urlencode(
        {
            "keywordSearch": keyword,
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
        }
    )
    url = f"{_NVD_BASE_URL}?{params}"
    parsed_url = urllib.parse.urlsplit(url)
    if (
        parsed_url.scheme != "https"
        or parsed_url.hostname != "services.nvd.nist.gov"
        or parsed_url.port not in (None, 443)
    ):
        raise NvdRequestError("Refusing request to an untrusted NVD endpoint")

    last_error: Optional[Exception] = None
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            _wait_for_rate_limit()
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "OpenShield/0.1 (github.com/openshield-org/openshield)"},
            )
            with NVD_REQUEST_LATENCY_SECONDS.time():
                with urllib.request.urlopen(  # nosec B310  # noqa: E501
                    req, timeout=10
                ) as resp:
                    return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code != 429:
                break
            time.sleep(30 * attempt)
        except Exception as exc:
            last_error = exc
            if attempt < _MAX_RETRIES:
                time.sleep(2**attempt)
    raise NvdRequestError(f"NVD request failed for {keyword!r}: {last_error}")


def query_nvd_strict(keyword: str, results_per_page: int = _RESULTS_PER_PAGE) -> list[dict]:
    """Return every NVD result, propagating terminal retrieval failure to the job queue."""
    cache_key = f"strict:{keyword}:{results_per_page}"
    if cache_key in _cache:
        return _cache[cache_key]

    start_index = 0
    total_results: Optional[int] = None
    results: list[dict] = []
    while total_results is None or start_index < total_results:
        page = _fetch_nvd_page(keyword, start_index, results_per_page)
        vulnerabilities = page.get("vulnerabilities", [])
        results.extend(parsed for item in vulnerabilities if (parsed := _parse_cve_item(item)) is not None)
        total_results = int(page.get("totalResults", len(vulnerabilities)))
        if not vulnerabilities:
            break
        start_index += len(vulnerabilities)
    _cache[cache_key] = results
    return results


def query_nvd(keyword: str, results_per_page: int = _RESULTS_PER_PAGE) -> list[dict]:
    """
    Query NVD for CVEs matching a keyword.

    Returns a list of parsed CVE dicts (may be empty).
    Never raises - all failures return [].

    Args:
        keyword: Search term, e.g. "Azure Storage Account"
        results_per_page: Max CVEs to fetch (default 5)
    """
    cache_key = f"{keyword}:{results_per_page}"
    if cache_key in _cache:
        logger.debug("NVD cache hit for: %s", keyword)
        return _cache[cache_key]

    try:
        results = query_nvd_strict(keyword, results_per_page)
    except NvdRequestError as exc:
        logger.warning("NVD lookup failed for '%s': %s", keyword, exc)
        results = []
    _cache[cache_key] = results
    return results
