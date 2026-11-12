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
    # JSON service-principal blob consumed by azure/login@v1 `creds:`.
    re.compile(r"AZURE_CREDENTIALS", re.IGNORECASE),
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


def _iter_scalar_strings(node: Any) -> List[str]:
    """Recursively collect every string key and scalar string value in a tree."""
    out: List[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str):
                out.append(key)
            out.extend(_iter_scalar_strings(value))
    elif isinstance(node, list):
        for item in node:
            out.extend(_iter_scalar_strings(item))
    elif isinstance(node, str):
        out.append(node)
    return out


def _strip_inline_comment(line: str) -> str:
    """Strip a trailing YAML comment from a single line.

    A ``#`` starts a comment only at the start of the line or when preceded by
    whitespace, and never inside a single- or double-quoted scalar.
    """
    in_single = in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double and (i == 0 or line[i - 1].isspace()):
            return line[:i]
    return line


def has_long_lived_credentials(yaml_content: str, parsed: Optional[Dict[str, Any]] = None) -> List[str]:
    """Return list of matched long-lived credential env var names found in YAML.

    Scans the parsed workflow's keys and scalar values rather than the raw text,
    so a credential name appearing only in a comment — whether on its own line
    or trailing a value (e.g. ``client-id: ... # migrated off ARM_CLIENT_SECRET``)
    — does not produce a false positive. When the content cannot be parsed, falls
    back to a text scan with full-line and inline comments stripped.
    """
    if parsed is None:
        parsed = parse_workflow(yaml_content)

    if isinstance(parsed, dict):
        haystack = "\n".join(_iter_scalar_strings(parsed))
    else:
        # Unparseable YAML: best-effort strip of full-line and inline comments.
        haystack = "\n".join(_strip_inline_comment(line) for line in yaml_content.splitlines())

    found: List[str] = []
    for pattern in _LONGTERM_CRED_PATTERNS:
        found.extend(pattern.findall(haystack))
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
            has_oidc_permission = str(top_perms.get("id-token") or "").lower() == "write"
        # Check job-level permissions if top-level not set
        if not has_oidc_permission:
            jobs = parsed.get("jobs") or {}
            for job in jobs.values():
                if not isinstance(job, dict):
                    continue
                job_perms = job.get("permissions") or {}
                if isinstance(job_perms, dict):
                    if str(job_perms.get("id-token") or "").lower() == "write":
                        has_oidc_permission = True
                        break
    else:
        has_oidc_permission = "id-token: write" in yaml_content

    has_azure_login = "azure/login" in yaml_content
    # Check ALL long-lived credential patterns against parsed values (comments excluded)
    has_any_long_lived_cred = bool(has_long_lived_credentials(yaml_content, parsed))
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
    """Return True if effective permissions are over-broad at any level.

    Evaluates both the top-level permissions block and every job-level
    override. A workflow is broad if:
    - Top-level block is write-all or grants 3+ sensitive write scopes, OR
    - Any job-level override grants write-all or 3+ sensitive write scopes.
    An absent top-level block is safe only when every job declares explicit
    permissions AND none of those per-job blocks are themselves broad.
    """

    def _block_is_broad(perms: Optional[Dict[str, str]]) -> bool:
        if perms is None:
            return False  # None means not declared at this level
        if isinstance(perms, str):
            return perms in ("write-all", "write")
        if not isinstance(perms, dict):
            return False
        if perms.get("all") in ("write-all", "write"):
            return True
        broad_count = sum(1 for k, v in perms.items() if str(v).lower() == "write" and k in _BROAD_PERMISSIONS)
        return broad_count >= 3

    # Check top-level permissions
    if permissions is not None and _block_is_broad(permissions):
        return True

    jobs = (parsed or {}).get("jobs") or {}

    if permissions is None:
        # No top-level block: safe only if every job declares explicit
        # non-broad permissions
        if not jobs:
            return True  # no jobs, treat as unconstrained
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            job_perms = job.get("permissions")
            if job_perms is None:
                return True  # job has no permissions declaration
            if _block_is_broad(job_perms):
                return True
        return False

    # Top-level block present and not broad: also check job-level overrides
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        job_perms = job.get("permissions")
        if job_perms is not None and _block_is_broad(job_perms):
            return True

    return False


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
