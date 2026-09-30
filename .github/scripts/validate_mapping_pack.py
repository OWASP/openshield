#!/usr/bin/env python3
"""Validate compliance mapping-pack semantics for every framework file.

Every control must carry evidence-based mapping metadata, not just exist in
the file (issue #302) - this is what stops a future PR from force-mapping a
rule into a framework with no rationale for the relationship, or leaving a
synthetic non-mapping (a rule this repository could not actually tie to a
numbered framework control) misclassified as if it were direct technical
evidence.

Runnable standalone (invoked from CI) or imported for unit testing against
fixture directories.
"""

import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any, Dict, List

VALID_MAPPING_TYPES = {"direct", "supporting", "organizational", "not_applicable"}
VALID_REVIEW_STATUSES = {"pending_review", "reviewed"}
VALID_PACK_STATUSES = {"current", "legacy"}
REQUIRED_PACK_FIELDS = (
    "mapping_pack_version",
    "mapping_pack_status",
    "mapping_pack_source",
    "mapping_pack_published",
)

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")

# A control ID this repository itself invented because the framework has no
# corresponding numbered control ("N/A-<category>-<number>"), or a control
# whose own name/description/rationale explicitly disclaims a real mapping,
# cannot be reported as "direct" technical evidence for that framework - a
# scan of a rule with no target control is not evidence for a control that
# does not exist. Checking substrings rather than only the ID prefix catches
# the same disclaimer being made in prose without the N/A- convention.
_NON_MAPPING_ID_PREFIX = "n/a"
_NON_MAPPING_PHRASES = ("not mapped", "not directly mapped", "no direct mapping", "not applicable")


def _is_disclaimed_non_mapping(control: Dict[str, Any]) -> bool:
    control_id = str(control.get("control_id", "")).strip().lower()
    if control_id.startswith(_NON_MAPPING_ID_PREFIX):
        return True
    haystack = " ".join(str(control.get(field, "")) for field in ("control_name", "description", "rationale")).lower()
    return any(phrase in haystack for phrase in _NON_MAPPING_PHRASES)


def _is_valid_iso_date(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        date.fromisoformat(value)
        return True
    except ValueError:
        return False


def validate_framework_dir(framework_dir: "str | Path") -> List[str]:
    """Return a list of human-readable failure strings; empty means valid."""
    failures: List[str] = []
    framework_dir = Path(framework_dir)

    for fpath in sorted(framework_dir.glob("*.json")):
        fname = fpath.name
        try:
            with open(fpath) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            failures.append(f"{fname}: could not parse - {e}")
            continue

        for field in REQUIRED_PACK_FIELDS:
            if not data.get(field):
                failures.append(f"{fname}: missing or empty top-level '{field}'")

        version = data.get("mapping_pack_version")
        if version is not None and not (isinstance(version, str) and _SEMVER_RE.match(version)):
            failures.append(f"{fname}: mapping_pack_version '{version}' is not a valid semantic version (X.Y.Z)")

        published = data.get("mapping_pack_published")
        if published is not None and not _is_valid_iso_date(published):
            failures.append(f"{fname}: mapping_pack_published '{published}' is not a valid ISO date (YYYY-MM-DD)")

        status = data.get("mapping_pack_status")
        if status is not None and status not in VALID_PACK_STATUSES:
            failures.append(f"{fname}: mapping_pack_status '{status}' not in {sorted(VALID_PACK_STATUSES)}")

        for rule_id, control in data.get("controls", {}).items():
            prefix = f"{fname}:{rule_id}"

            mapping_type = control.get("mapping_type")
            if mapping_type not in VALID_MAPPING_TYPES:
                failures.append(f"{prefix}: mapping_type '{mapping_type}' not in {sorted(VALID_MAPPING_TYPES)}")

            for field in ("evidence_type", "primary_source", "rationale"):
                value = control.get(field)
                if not isinstance(value, str) or not value.strip():
                    failures.append(f"{prefix}: '{field}' must be a non-empty string")

            review_status = control.get("review_status")
            if review_status not in VALID_REVIEW_STATUSES:
                failures.append(f"{prefix}: review_status '{review_status}' not in {sorted(VALID_REVIEW_STATUSES)}")

            owner = control.get("owner")
            if owner is not None and not (isinstance(owner, str) and owner.strip()):
                failures.append(f"{prefix}: 'owner' must be null or a non-empty string")

            review_date = control.get("review_date")
            if review_date is not None and not _is_valid_iso_date(review_date):
                failures.append(f"{prefix}: review_date '{review_date}' is not a valid ISO date (YYYY-MM-DD)")

            # A control cannot be marked reviewed without an accountable owner
            # and a review date - otherwise "reviewed" is unverifiable.
            if review_status == "reviewed" and (not owner or not review_date):
                failures.append(f"{prefix}: review_status is 'reviewed' but owner and/or review_date is missing")

            # not_applicable/organizational controls must not claim to be
            # measured by an automated scan.
            if (
                mapping_type in ("not_applicable", "organizational")
                and control.get("evidence_type") == "automated_configuration_scan"
            ):
                failures.append(
                    f"{prefix}: mapping_type '{mapping_type}' cannot have evidence_type 'automated_configuration_scan'"
                )

            # A control this repository itself marked as having no real
            # framework counterpart (synthetic N/A-* ID, or its own text
            # disclaiming a direct mapping) cannot be reported as direct
            # technical evidence - that is exactly the overstatement issue
            # #302 exists to close.
            if mapping_type == "direct" and _is_disclaimed_non_mapping(control):
                failures.append(
                    f"{prefix}: mapping_type is 'direct' but control_id/name/description/rationale disclaims a "
                    "real mapping (N/A-* ID or 'not mapped'/'no direct mapping' text) - must be 'not_applicable'"
                )

    return failures


def main() -> int:
    framework_dir = sys.argv[1] if len(sys.argv) > 1 else "compliance/frameworks"
    print(f"=== Validating compliance mapping-pack semantics in {framework_dir} ===")
    failures = validate_framework_dir(framework_dir)
    if failures:
        print("COMPLIANCE MAPPING SEMANTICS FAILURES:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("All compliance mappings carry valid mapping-pack semantics.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
