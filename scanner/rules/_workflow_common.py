"""Shared helpers for CI/CD workflow security scan rules (AZ-CI-*)."""

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_SHA_PIN_RE = re.compile(r"^[^@]+@[0-9a-f]{40}$")

_BROAD_PERMISSIONS = {
    "contents": "write",
    "actions": "write",
    "packages": "write",
    "deployments": "write",
    "id-token": "write",
    "pull-requests": "write",
    "issues": "write",
    "security-events": "write",
}

_DANGEROUS_TRIGGERS = {"pull_request_target", "workflow_run"}

_LONGTERM_CRED_PATTERNS = [
    re.compile(r"AZURE_CLIENT_SECRET", re.IGNORECASE),
    re.compile(r"AZURE_PASSWORD", re.IGNORECASE),
    re.compile(r"ARM_CLIENT_SECRET", re.IGNORECASE),
    re.compile(r"ARM_ACCESS_KEY", re.IGNORECASE),
    re.compile(r"AZURE_STORAGE_KEY", re.IGNORECASE),
]


def parse_workflow(yaml_content: str) -> Optional[Dict[str, Any]]:
    """Parse YAML workflow content; returns None on malformed input."""
    try:
        import yaml

        return yaml.safe_load(yaml_content) or {}
    except Exception as exc:
        logger.warning("Failed to parse workflow YAML: %s", exc)
        return None


def is_action_pinned(uses: str) -> bool:
    """Return True if a uses reference is pinned to a full commit SHA."""
    if not uses or uses.startswith("./") or uses.startswith("docker://"):
        return True
    return bool(_SHA_PIN_RE.match(uses.strip()))


def collect_uses(workflow: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Return all (job_id, uses) pairs from a parsed workflow dict.

    Collects both step-level uses (regular actions) and job-level uses
    (reusable workflow calls). Handles null/empty job definitions safely.
    """
    results = []
    jobs = workflow.get("jobs") or {}
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        # Job-level uses: reusable workflow call
        job_uses = job.get("uses")
        if job_uses:
            results.append((job_id, job_uses))
        # Step-level uses: regular action references
        steps = job.get("steps") or []
        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses")
            if uses:
                results.append((job_id, uses))
    return results


def has_long_lived_credentials(yaml_content: str) -> List[str]:
    """Return list of matched long-lived credential env var names found in YAML.

    Excludes YAML comment lines (lines whose first non-whitespace char is #)
    to avoid false positives from changelog-style migration comments.
    """
    # Strip comment lines before scanning
    non_comment_lines = [line for line in yaml_content.splitlines() if not line.lstrip().startswith("#")]
    non_comment_content = "\n".join(non_comment_lines)
    found = []
    for pattern in _LONGTERM_CRED_PATTERNS:
        matches = pattern.findall(non_comment_content)
        found.extend(matches)
    return found


def uses_workload_identity(yaml_content: str, parsed: Optional[Dict[str, Any]] = None) -> bool:
    """Return True if the workflow uses OIDC workload identity federation.

    Checks both top-level and job-level permissions blocks for id-token: write,
    since per-job least-privilege is a recommended secure pattern. Also verifies
    azure/login is present and no long-lived credential is used outside comments.
    """
    has_oidc_permission = False
    if parsed is not None:
        # Check top-level permissions
        top_perms = parsed.get("permissions") or {}
        if isinstance(top_perms, dict):
            has_oidc_permission = top_perms.get("id-token", "").lower() == "write"
        # Check job-level permissions if top-level not set
        if not has_oidc_permission:
            jobs = parsed.get("jobs") or {}
            for job in jobs.values():
                if not isinstance(job, dict):
                    continue
                job_perms = job.get("permissions") or {}
                if isinstance(job_perms, dict):
                    if job_perms.get("id-token", "").lower() == "write":
                        has_oidc_permission = True
                        break
    else:
        has_oidc_permission = "id-token: write" in yaml_content

    has_azure_login = "azure/login" in yaml_content
    # Check ALL long-lived credential patterns, excluding comment lines
    has_any_long_lived_cred = bool(has_long_lived_credentials(yaml_content))
    return has_oidc_permission and has_azure_login and not has_any_long_lived_cred


def get_top_level_permissions(workflow: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Return top-level permissions block, or None if not defined."""
    perms = workflow.get("permissions")
    if perms is None:
        return None
    if isinstance(perms, str):
        return {"all": perms}
    return perms if isinstance(perms, dict) else None


def is_permissions_broad(
    permissions: Optional[Dict[str, str]],
    parsed: Optional[Dict[str, Any]] = None,
) -> bool:
    """Return True if permissions grant write-all or multiple broad scopes.

    An absent top-level permissions block is only treated as broad when jobs
    also lack explicit per-job permissions declarations. Per-job least privilege
    (no top-level block, every job declares its own) is a recommended secure
    pattern and must not be flagged.
    """
    if permissions is None:
        if parsed is not None:
            jobs = parsed.get("jobs") or {}
            if jobs and all(isinstance(job, dict) and job.get("permissions") is not None for job in jobs.values()):
                return False
        return True
    if permissions.get("all") in ("write-all", "write"):
        return True
    broad_count = sum(1 for k, v in permissions.items() if v == "write" and k in _BROAD_PERMISSIONS)
    return broad_count >= 3


def get_dangerous_triggers(workflow: Dict[str, Any]) -> List[str]:
    """Return list of dangerous triggers present in the workflow."""
    on = workflow.get("on") or workflow.get(True) or {}
    if isinstance(on, str):
        on = {on: {}}
    if isinstance(on, list):
        on = {t: {} for t in on}
    return [t for t in _DANGEROUS_TRIGGERS if t in on]


def build_ci_finding(
    rule_id: str,
    rule_name: str,
    severity: str,
    category: str,
    frameworks: Dict[str, str],
    description: str,
    remediation: str,
    playbook: str,
    owner: str,
    repo: str,
    workflow_path: str,
    metadata: Dict[str, Any],
) -> Dict[str, Any]:
    """Build a standardised CI/CD finding dict."""
    resource_id = f"github/{owner}/{repo}/workflows/{workflow_path}"
    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": severity,
        "category": category,
        "resource_id": resource_id,
        "resource_name": workflow_path,
        "resource_type": "GitHub/WorkflowFile",
        "description": description,
        "remediation": remediation,
        "playbook": playbook,
        "frameworks": frameworks,
        "metadata": {
            "owner": owner,
            "repo": repo,
            "workflow_path": workflow_path,
            **metadata,
        },
    }
