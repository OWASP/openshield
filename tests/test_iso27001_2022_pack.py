"""ISO/IEC 27001:2022 mapping-pack invariants (issue #358)."""

import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "compliance" / "frameworks" / "iso27001.json"
RULES_DIR = ROOT / "scanner" / "rules"

# ISO/IEC 27001:2022 Annex A has 93 controls: A.5.1-5.37, A.6.1-6.8, A.7.1-7.14, A.8.1-8.34.
_ANNEX_A_2022 = re.compile(r"^A\.(5\.([1-9]|[12]\d|3[0-7])|6\.[1-8]|7\.([1-9]|1[0-4])|8\.([1-9]|[12]\d|3[0-4]))$")
_SYNTHETIC_NON_MAPPING = re.compile(r"^N/A-[A-Z]+-\d{3}$")
# Top-level clauses that exist only in the 2013 Annex A (A.9 to A.18), plus the 2013 edition label.
_2013_ONLY = re.compile(r"\bA\.(9|1[0-8])\.\d+(\.\d+)?\b|27001:2013")


@pytest.fixture(scope="module")
def pack():
    return json.loads(PACK.read_text())


def _rule_modules():
    for path in sorted(RULES_DIR.glob("az_*.py")):
        spec = importlib.util.spec_from_file_location(path.stem, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        yield module


def test_pack_declares_the_2022_edition(pack):
    assert pack["framework"] == "ISO/IEC 27001:2022"
    assert pack["version"] == "2022"
    assert pack["mapping_pack_status"] == "current"
    # The edition changed, so this is a new major version of the pack.
    assert int(pack["mapping_pack_version"].split(".")[0]) >= 2


def test_every_control_id_is_a_2022_annex_a_control_or_a_declared_non_mapping(pack):
    bad = {
        rule_id: control["control_id"]
        for rule_id, control in pack["controls"].items()
        if not (_ANNEX_A_2022.match(control["control_id"]) or _SYNTHETIC_NON_MAPPING.match(control["control_id"]))
    }
    assert bad == {}


def test_no_2013_control_number_or_edition_label_survives_anywhere_in_the_pack(pack):
    leftovers = {
        (rule_id, field): value
        for rule_id, control in pack["controls"].items()
        for field, value in control.items()
        if isinstance(value, str) and _2013_ONLY.search(value)
    }
    assert leftovers == {}
    assert not _2013_ONLY.search(pack["mapping_pack_source"])


def test_a_control_id_always_carries_the_same_name(pack):
    names: dict = {}
    for control in pack["controls"].values():
        if _SYNTHETIC_NON_MAPPING.match(control["control_id"]):
            continue
        assert names.setdefault(control["control_id"], control["control_name"]) == control["control_name"]


def test_sources_and_rationales_cite_the_control_each_entry_maps_to(pack):
    for rule_id, control in pack["controls"].items():
        if _SYNTHETIC_NON_MAPPING.match(control["control_id"]):
            continue
        assert control["primary_source"] == f"ISO/IEC 27001:2022, Annex A control {control['control_id']}", rule_id
        assert control["control_id"] in control["rationale"], rule_id


def test_controls_new_in_2022_are_used_where_they_fit_better(pack):
    used = {control["control_id"] for control in pack["controls"].values()}
    assert {"A.8.9", "A.8.16"} <= used


def test_the_remap_does_not_mark_anything_reviewed(pack):
    assert {control["review_status"] for control in pack["controls"].values()} == {"pending_review"}


def test_the_pack_covers_exactly_the_shipped_rules(pack):
    assert set(pack["controls"]) == {module.RULE_ID for module in _rule_modules()}


def test_each_rules_own_iso_mapping_matches_the_pack():
    """A rule's FRAMEWORKS["ISO27001"] is shown on findings, so it must not drift from the scored pack."""
    pack_controls = json.loads(PACK.read_text())["controls"]
    drift = {
        module.RULE_ID: (module.FRAMEWORKS.get("ISO27001"), pack_controls[module.RULE_ID]["control_id"])
        for module in _rule_modules()
        if module.FRAMEWORKS.get("ISO27001") != pack_controls[module.RULE_ID]["control_id"]
    }
    assert drift == {}
