"""GitHub REST API client for CI/CD workflow security scan rules.

Authenticates via GitHub App installation token (preferred) with an explicit
GITHUB_TOKEN or fine-grained PAT as fallback. Returns None on any auth,
permission, or network failure so callers can return UNKNOWN instead of
crashing the scan engine.

Authentication priority:
  1. GitHub App: GITHUB_APP_ID + GITHUB_APP_PRIVATE_KEY + GITHUB_APP_INSTALLATION_ID
  2. GITHUB_TOKEN (Actions token or fine-grained PAT)
"""

import base64
import logging
import os
import time
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

_GITHUB_API = "https://api.github.com"
_UNSET = object()

# Rate-limit handling: how many times to wait-and-retry a rate-limited request,
# and the longest single wait we will honour before giving up (UNKNOWN).
_MAX_RATE_LIMIT_RETRIES = 3
_MAX_RATE_LIMIT_WAIT_SECONDS = 60


def _rate_limit_wait_seconds(resp: "requests.Response") -> Optional[int]:
    """Return seconds to wait if the response is a rate-limit rejection, else None.

    GitHub signals rate limiting with HTTP 429, or HTTP 403 together with
    ``X-RateLimit-Remaining: 0`` (primary limit) or a ``Retry-After`` header
    (secondary limit). Honour ``Retry-After`` when present, otherwise derive the
    wait from ``X-RateLimit-Reset`` (an epoch timestamp). Returns 0 when the
    response is rate-limited but carries no usable timing hint.
    """
    headers = resp.headers
    remaining = headers.get("X-RateLimit-Remaining")
    is_rate_limited = resp.status_code == 429 or (
        resp.status_code == 403 and (remaining == "0" or "Retry-After" in headers)
    )
    if not is_rate_limited:
        return None

    retry_after = headers.get("Retry-After")
    if retry_after is not None:
        try:
            return max(0, int(float(retry_after)))
        except (TypeError, ValueError):
            pass
    reset = headers.get("X-RateLimit-Reset")
    if reset is not None:
        try:
            return max(0, int(float(reset)) - int(time.time()))
        except (TypeError, ValueError):
            pass
    return 0


def _get_app_token() -> Optional[str]:
    """Generate a GitHub App installation access token."""
    app_id = os.environ.get("GITHUB_APP_ID", "")
    private_key = os.environ.get("GITHUB_APP_PRIVATE_KEY", "")
    installation_id = os.environ.get("GITHUB_APP_INSTALLATION_ID", "")
    if not (app_id and private_key and installation_id):
        return None
    try:
        import jwt as pyjwt

        now = int(time.time())
        payload = {"iat": now - 60, "exp": now + 540, "iss": app_id}
        app_token = pyjwt.encode(payload, private_key, algorithm="RS256")
        resp = requests.post(
            f"{_GITHUB_API}/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {app_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=15,
        )
        if resp.status_code == 201:
            return resp.json().get("token")
        logger.error(
            "GitHub App token request failed (HTTP status indicates rejection)"
        )  # nosemgrep: python-logger-credential-disclosure
    except Exception as exc:
        logger.error(  # nosemgrep: python-logger-credential-disclosure
            "GitHub App token generation failed (check GITHUB_APP_* env vars): %s",
            type(exc).__name__,
        )
    return None


def _get_token() -> Optional[str]:
    """Return an authentication token, preferring App auth over PAT."""
    token = _get_app_token()
    if token:
        return token
    token = os.environ.get("GITHUB_TOKEN", "")
    return token if token else None


class GitHubClient:
    """Wraps the GitHub REST API for CI/CD workflow security scan rules.

    Instantiate once per scan and share across all AZ-CI rule modules.
    Every method logs on failure and returns None so a missing token or
    inaccessible repository never crashes the scan engine. Callers must
    treat None as UNKNOWN, not as a compliant result.
    """

    def __init__(self, owner: str, repo: str, token: Optional[str] = None) -> None:
        """
        Args:
            owner: GitHub organisation or user name.
            repo:  Repository name.
            token: Auth token. Defaults to auto-detection via _get_token().
        """
        self.owner = owner
        self.repo = repo
        self._token = token or _get_token()
        self._workflows_cache: Any = _UNSET
        self._workflow_files_cache: Dict[str, Any] = {}

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _get(self, path: str, **kwargs: Any) -> Optional[requests.Response]:
        """GET a GitHub API path; returns None on any error.

        Honours GitHub rate limiting (HTTP 429, or 403 with
        ``X-RateLimit-Remaining: 0``): waits for the ``Retry-After`` /
        ``X-RateLimit-Reset`` interval and retries a bounded number of times,
        then logs a clear warning and returns None (UNKNOWN) if still limited.
        """
        url = f"{_GITHUB_API}{path}"
        try:
            for attempt in range(_MAX_RATE_LIMIT_RETRIES + 1):
                resp = requests.get(url, headers=self._headers(), timeout=15, **kwargs)

                wait = _rate_limit_wait_seconds(resp)
                if wait is not None:
                    if attempt >= _MAX_RATE_LIMIT_RETRIES:
                        logger.warning(
                            "GitHub API rate limit (HTTP %d) not cleared after %d retries for %s; returning UNKNOWN",
                            resp.status_code,
                            _MAX_RATE_LIMIT_RETRIES,
                            url,
                        )
                        return None
                    sleep_for = min(wait, _MAX_RATE_LIMIT_WAIT_SECONDS)
                    logger.warning(
                        "GitHub API rate limited (HTTP %d) for %s; waiting %ds before retry %d/%d",
                        resp.status_code,
                        url,
                        sleep_for,
                        attempt + 1,
                        _MAX_RATE_LIMIT_RETRIES,
                    )
                    time.sleep(sleep_for)
                    continue

                if resp.status_code == 403:
                    logger.warning("GitHub API permission denied for %s", url)
                    return None
                if resp.status_code == 404:
                    logger.warning("GitHub resource not found: %s", url)
                    return None
                resp.raise_for_status()
                return resp
            return None
        except Exception as exc:
            logger.error("GitHub API request failed for %s: %s", url, exc, exc_info=True)
            return None

    def get_workflows(self) -> Optional[List[Dict[str, Any]]]:
        """Return all workflow definitions for the repository.

        Follows the Link header to paginate beyond the 100-item page size,
        so repositories with >100 workflows are fully enumerated.
        Returns a list (including empty) on success, None on failure.
        """
        if self._workflows_cache is not _UNSET:
            return self._workflows_cache
        workflows: List[Dict[str, Any]] = []
        url: Optional[str] = f"{_GITHUB_API}/repos/{self.owner}/{self.repo}/actions/workflows"
        params: Dict[str, Any] = {"per_page": 100}
        while url:
            resp = self._get(url.replace(_GITHUB_API, ""), params=params)
            if resp is None:
                self._workflows_cache = None
                return None
            try:
                data = resp.json()
                workflows.extend(data.get("workflows", []))
                # Follow Link: <url>; rel="next" header for next page
                link_header = resp.headers.get("Link", "")
                next_url = None
                for part in link_header.split(","):
                    part = part.strip()
                    if 'rel="next"' in part:
                        next_url = part.split(";")[0].strip().strip("<>")
                        break
                url = next_url
                params = {}  # URL already contains query params for subsequent pages
            except Exception as exc:
                logger.error("Failed to parse workflows response: %s", exc, exc_info=True)
                self._workflows_cache = None
                return None
        self._workflows_cache = workflows
        return self._workflows_cache

    def get_workflow_content(self, path: str) -> Optional[str]:
        """Return the decoded YAML content of a workflow file.

        Args:
            path: Workflow file path e.g. '.github/workflows/ci.yml'
        Returns:
            Decoded YAML string, or None on failure/missing permissions.
        """
        if path in self._workflow_files_cache:
            return self._workflow_files_cache[path]
        resp = self._get(f"/repos/{self.owner}/{self.repo}/contents/{path}")
        if resp is None:
            self._workflow_files_cache[path] = None
            return None
        try:
            data = resp.json()
            content_b64 = data.get("content", "")
            if not content_b64 and data.get("download_url"):
                # File >1 MB: contents API returns empty content with a download_url
                logger.warning(
                    "Workflow file %s exceeds 1 MB — contents API returned empty; treating as UNKNOWN",
                    path,
                )
                self._workflow_files_cache[path] = None
                return None
            decoded = base64.b64decode(content_b64).decode("utf-8")
            self._workflow_files_cache[path] = decoded
            return decoded
        except Exception as exc:
            logger.error("Failed to decode workflow file %s: %s", path, exc, exc_info=True)
            self._workflow_files_cache[path] = None
            return None

    def get_repo_info(self) -> Optional[Dict[str, Any]]:
        """Return repository metadata (visibility, default branch, etc.)."""
        resp = self._get(f"/repos/{self.owner}/{self.repo}")
        if resp is None:
            return None
        try:
            return resp.json()
        except Exception as exc:
            logger.error("Failed to parse repo info: %s", exc, exc_info=True)
            return None

    def get_workflow_permissions(self) -> Optional[str]:
        """Return the repository's default GITHUB_TOKEN workflow permissions.

        Reads GET /repos/{owner}/{repo}/actions/permissions/workflow, the only
        endpoint that exposes default_workflow_permissions. Requires the token
        to have administration: read on the repository.

        Returns "read" or "write" when the setting can be read, or None when
        the endpoint is unavailable (missing administration: read, 403/404, or
        any other failure). Callers MUST treat None as UNKNOWN, never as a
        compliant default.
        """
        resp = self._get(f"/repos/{self.owner}/{self.repo}/actions/permissions/workflow")
        if resp is None:
            return None
        try:
            return resp.json().get("default_workflow_permissions")
        except Exception as exc:
            logger.error("Failed to parse workflow permissions: %s", exc, exc_info=True)
            return None
