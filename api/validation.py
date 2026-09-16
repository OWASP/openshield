"""Reusable allowlist and shape validation for untrusted API input."""

from __future__ import annotations

import re
import uuid
from typing import Any, Iterable

from openshield.severity import ACCEPTED_SEVERITIES, SeverityContractError, normalize_severity


class ValidationError(ValueError):
    """Raised when a client-controlled value violates the public API contract."""


VALIDATION_ERROR_MESSAGE = "Invalid request parameters"


RULE_ID_RE = re.compile(r"^[A-Z0-9]+(?:-[A-Z0-9]+)*$")
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")

SEVERITIES = ACCEPTED_SEVERITIES
CATEGORIES = frozenset(
    {
        "Backup",
        "Compute",
        "Database",
        "Identity",
        "Key Vault",
        "KeyVault",
        "Kubernetes",
        "Network",
        "PostQuantum",
        "Serverless",
        "Storage",
        "Supply Chain",
    }
)

MAX_API_KEY_LENGTH = 4096
MAX_MODEL_LENGTH = 128
MAX_QUESTION_LENGTH = 4000
MAX_FINDINGS = 1000
MAX_FINDING_TEXT_LENGTH = 8192


def require_json_object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError("Request body must be a JSON object")
    return value


def reject_unknown_fields(value: dict[str, Any], allowed: Iterable[str]) -> None:
    unknown = set(value) - set(allowed)
    if unknown:
        raise ValidationError(f"Unsupported field: {sorted(unknown)[0]}")


def bounded_string(
    value: Any,
    field: str,
    *,
    minimum: int = 1,
    maximum: int,
    pattern: re.Pattern[str] | None = None,
) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a string")
    result = value.strip()
    if len(result) < minimum:
        raise ValidationError(f"{field} is required")
    if len(result) > maximum:
        raise ValidationError(f"{field} must be at most {maximum} characters")
    if pattern is not None and pattern.fullmatch(result) is None:
        raise ValidationError(f"{field} has an invalid format")
    return result


def choice(value: Any, field: str, allowed: Iterable[str], *, case: str = "preserve") -> str:
    result = bounded_string(value, field, maximum=128)
    if case == "upper":
        result = result.upper()
    elif case == "lower":
        result = result.lower()
    allowed_set = set(allowed)
    if result not in allowed_set:
        raise ValidationError(f"Unsupported {field}")
    return result


def canonical_choice(value: Any, field: str, allowed: Iterable[str]) -> str:
    """Return the allowlisted spelling while accepting case-insensitive input."""
    result = bounded_string(value, field, maximum=128)
    canonical = {item.casefold(): item for item in allowed}
    try:
        return canonical[result.casefold()]
    except KeyError as exc:
        raise ValidationError(f"Unsupported {field}") from exc


def severity_value(value: Any, field: str = "severity") -> str:
    """Validate a public severity value and return its canonical ID."""
    bounded_string(value, field, maximum=128)
    try:
        return normalize_severity(value)
    except SeverityContractError as exc:
        raise ValidationError(f"Unsupported {field}") from exc


def uuid_string(value: Any, field: str) -> str:
    result = bounded_string(value, field, maximum=36)
    try:
        parsed = uuid.UUID(result)
    except (ValueError, AttributeError) as exc:
        raise ValidationError(f"{field} must be a valid UUID") from exc
    if str(parsed) != result.lower():
        raise ValidationError(f"{field} must use canonical UUID format")
    return str(parsed)


def positive_integer(value: int, field: str) -> int:
    if value <= 0:
        raise ValidationError(f"{field} must be a positive integer")
    return value


def findings_list(value: Any, *, required: bool = False) -> list[dict[str, Any]]:
    if value is None:
        if required:
            raise ValidationError("findings is required")
        return []
    if not isinstance(value, list):
        raise ValidationError("findings must be a list")
    if required and not value:
        raise ValidationError("findings must not be empty")
    if len(value) > MAX_FINDINGS:
        raise ValidationError(f"findings must contain at most {MAX_FINDINGS} items")

    text_fields = (
        "rule_id",
        "rule_name",
        "title",
        "severity",
        "resource_name",
        "description",
        "remediation",
    )
    validated: list[dict[str, Any]] = []
    for index, finding in enumerate(value):
        if not isinstance(finding, dict):
            raise ValidationError(f"findings[{index}] must be an object")
        for key in text_fields:
            field_value = finding.get(key)
            if field_value is not None and (
                not isinstance(field_value, str) or len(field_value) > MAX_FINDING_TEXT_LENGTH
            ):
                raise ValidationError(
                    f"findings[{index}].{key} must be a string of at most {MAX_FINDING_TEXT_LENGTH} characters"
                )
        normalized = dict(finding)
        if normalized.get("severity") is not None:
            normalized["severity"] = severity_value(normalized["severity"], f"findings[{index}].severity")
        validated.append(normalized)
    return validated
