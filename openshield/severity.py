"""Canonical finding-severity contract shared by scanner and API code."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping

_CONTRACT_PATH = Path(__file__).resolve().parent.parent / "contracts" / "severity.v1.json"
_SQL_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
_HEX_COLOR = re.compile(r"^#[0-9A-Fa-f]{6}$")
_CONTRACT_VERSION = re.compile(r"^[1-9][0-9]*\.[0-9]+\.[0-9]+$")
_SUPPORTED_TONES = frozenset({"critical", "danger", "warning", "success", "neutral"})


class SeverityContractError(ValueError):
    """Raised when a value is outside the versioned severity contract."""


@dataclass(frozen=True)
class SeverityLevel:
    """One canonical finding severity and its cross-product semantics."""

    id: str
    rank: int
    score_weight: int
    risk_score: int
    label: str
    color: str
    tone: str


def _load_contract() -> tuple[str, tuple[SeverityLevel, ...], Mapping[str, str]]:
    with _CONTRACT_PATH.open(encoding="utf-8") as handle:
        raw = json.load(handle)

    if raw.get("contract") != "openshield.finding-severity":
        raise RuntimeError("Unexpected severity contract identifier")

    version = raw.get("version")
    if not isinstance(version, str) or _CONTRACT_VERSION.fullmatch(version) is None:
        raise RuntimeError("Severity contract version must use major.minor.patch")

    levels = tuple(SeverityLevel(**item) for item in raw.get("levels", []))
    if not levels:
        raise RuntimeError("Severity contract must define at least one level")

    ids = [level.id for level in levels]
    ranks = [level.rank for level in levels]
    if any(
        isinstance(level.rank, bool)
        or not isinstance(level.rank, int)
        or isinstance(level.score_weight, bool)
        or not isinstance(level.score_weight, int)
        or isinstance(level.risk_score, bool)
        or not isinstance(level.risk_score, int)
        for level in levels
    ):
        raise RuntimeError("Severity ranks, weights, and risk scores must be integers")
    if any(not isinstance(level_id, str) or level_id != level_id.strip().upper() for level_id in ids):
        raise RuntimeError("Severity IDs must be canonical uppercase values")
    if len(ids) != len(set(ids)) or len(ranks) != len(set(ranks)):
        raise RuntimeError("Severity IDs and ranks must be unique")
    if any(level.score_weight < 0 or level.risk_score < 0 for level in levels):
        raise RuntimeError("Severity weights and risk scores cannot be negative")
    if any(
        not isinstance(level.label, str)
        or not level.label.strip()
        or not isinstance(level.tone, str)
        or level.tone not in _SUPPORTED_TONES
        or not isinstance(level.color, str)
        or _HEX_COLOR.fullmatch(level.color) is None
        for level in levels
    ):
        raise RuntimeError("Severity labels, tones, and six-digit hex colors are required")

    ordered = sorted(levels, key=lambda level: level.rank)
    if any(
        lower.score_weight > higher.score_weight or lower.risk_score > higher.risk_score
        for lower, higher in zip(ordered, ordered[1:])
    ):
        raise RuntimeError("Severity weights and risk scores must increase with rank")

    by_id = {level.id: level for level in levels}
    if "CRITICAL" not in by_id or by_id["CRITICAL"].rank != max(ranks):
        raise RuntimeError("CRITICAL must be the highest-ranked severity")

    aliases = raw.get("aliases", {})
    if not isinstance(aliases, dict):
        raise RuntimeError("Severity aliases must be an object")
    normalized_aliases: dict[str, str] = {}
    for source, target in aliases.items():
        source_id = str(source).strip().upper()
        target_id = str(target).strip().upper()
        if (
            source != source_id
            or target != target_id
            or source_id in by_id
            or target_id not in by_id
            or source_id in normalized_aliases
        ):
            raise RuntimeError("Severity aliases must map non-canonical names to canonical IDs")
        normalized_aliases[source_id] = target_id

    return version, levels, MappingProxyType(normalized_aliases)


CONTRACT_VERSION, LEVELS, ALIASES = _load_contract()
LEVEL_BY_ID: Mapping[str, SeverityLevel] = MappingProxyType({level.id: level for level in LEVELS})
CANONICAL_SEVERITIES = frozenset(LEVEL_BY_ID)
ACCEPTED_SEVERITIES = frozenset((*CANONICAL_SEVERITIES, *ALIASES))
SEVERITY_WEIGHTS: Mapping[str, int] = MappingProxyType({level.id: level.score_weight for level in LEVELS})


def normalize_severity(value: Any) -> str:
    """Return a canonical severity ID or reject the value explicitly."""
    if not isinstance(value, str) or not value.strip():
        raise SeverityContractError("severity must be a non-empty string")
    candidate = value.strip().upper()
    candidate = ALIASES.get(candidate, candidate)
    if candidate not in LEVEL_BY_ID:
        raise SeverityContractError(f"unsupported severity: {value!r}")
    return candidate


def severity_level(value: Any) -> SeverityLevel:
    return LEVEL_BY_ID[normalize_severity(value)]


def severity_rank(value: Any) -> int:
    return severity_level(value).rank


def severity_weight(value: Any) -> int:
    return severity_level(value).score_weight


def severity_risk_score(value: Any) -> int:
    return severity_level(value).risk_score


def severity_from_rank(rank: int) -> str:
    for level in LEVELS:
        if level.rank == rank:
            return level.id
    raise SeverityContractError(f"unsupported severity rank: {rank!r}")


def score_findings(findings: Iterable[Mapping[str, Any]]) -> int:
    deduction = sum(severity_weight(finding.get("severity")) for finding in findings)
    return max(0, 100 - deduction)


def score_counts(counts: Mapping[str, int]) -> int:
    deduction = 0
    for severity, count in counts.items():
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise SeverityContractError("severity counts must be non-negative integers")
        deduction += severity_weight(severity) * count
    return max(0, 100 - deduction)


def severity_rank_sql(column: str) -> str:
    """Return a CASE expression derived from the contract for trusted SQL identifiers."""
    if _SQL_IDENTIFIER.fullmatch(column) is None:
        raise ValueError("column must be a trusted SQL identifier")
    cases = " ".join(f"WHEN '{level.id}' THEN {level.rank}" for level in LEVELS)
    return f"CASE UPPER({column}) {cases} ELSE -1 END"
