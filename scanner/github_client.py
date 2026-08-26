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
    except Exception:
        logger.error(
            "GitHub App token generation failed (check GITHUB_APP_* env vars)"
        )  # nosemgrep: python-logger-credential-disclosure
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
        """GET a GitHub API path; returns None on any error."""
        url = f"{_GITHUB_API}{path}"
        try:
            resp = requests.get(url, headers=self._headers(), timeout=15, **kwargs)
            if resp.status_code == 403:
                logger.warning("GitHub API permission denied for %s", url)
                return None
            if resp.status_code == 404:
                logger.warning("GitHub resource not found: %s", url)
                return None
            resp.raise_for_status()
            return resp
        except Exception as exc:
            logger.error("GitHub API request failed for %s: %s", url, exc)
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
                logger.error("Failed to parse workflows response: %s", exc)
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
            logger.error("Failed to decode workflow file %s: %s", path, exc)
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
            logger.error("Failed to parse repo info: %s", exc)
            return None
