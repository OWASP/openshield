"""Shared opt-in policy metadata for enterprise storage controls."""

from typing import Any, Mapping, Optional

from scanner.evaluation import APPROVED_EXCEPTION, POLICY_NOT_REQUIRED


def tags_for(resource: Any) -> Mapping[str, Any]:
    """Return resource tags, tolerating SDK objects and test doubles."""
    tags = getattr(resource, "tags", None)
    return tags if isinstance(tags, Mapping) else {}


def tag_true(resource: Any, name: str) -> bool:
    value = tags_for(resource).get(name)
    return str(value).strip().lower() in {"1", "true", "yes", "required", "critical"}


def approved_exception(resource: Any) -> bool:
    """Require an explicit approval marker; free-form exception text is not enough."""
    return tag_true(resource, "oshield:exception-approved")


def policy_exemption(resource: Any, requirement_tag: str) -> Optional[str]:
    """Return why an opt-in policy does not apply, or ``None`` when it does.

    The reason is the NOT_APPLICABLE reason_code evaluate() reports.
    """
    if not tag_true(resource, requirement_tag):
        return POLICY_NOT_REQUIRED
    if approved_exception(resource):
        return APPROVED_EXCEPTION
    return None


def policy_required(resource: Any, requirement_tag: str) -> bool:
    """Use explicit opt-in metadata to avoid assuming every account is critical."""
    return policy_exemption(resource, requirement_tag) is None
