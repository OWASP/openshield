"""Tests for playbooks/cli/jit_policy_merge.py — the AZ-CMP-007 remediation helper.

These prove the fix_az_cmp_007.sh remediation preserves an existing multi-VM JIT
policy instead of overwriting it with only the VM being remediated.
"""

import importlib.util
import pathlib

_MOD_PATH = pathlib.Path(__file__).resolve().parents[1] / "playbooks" / "cli" / "jit_policy_merge.py"
_spec = importlib.util.spec_from_file_location("jit_policy_merge", _MOD_PATH)
jit_policy_merge = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(jit_policy_merge)


def test_merge_preserves_existing_vms():
    """Remediating one VM must not drop other VMs already in the default policy."""
    existing = {
        "kind": "Basic",
        "properties": {"virtualMachines": [{"id": "/vm/other", "ports": [{"number": 22}]}]},
    }
    entry = jit_policy_merge.build_vm_entry("/vm/new", [22, 3389])
    merged = jit_policy_merge.merge_policy(existing, entry)
    ids = {vm["id"] for vm in merged["properties"]["virtualMachines"]}
    assert ids == {"/vm/other", "/vm/new"}


def test_merge_replaces_same_vm_without_duplicating():
    """Re-remediating the same VM updates its entry in place rather than duplicating it."""
    existing = {"properties": {"virtualMachines": [{"id": "/vm/x", "ports": [{"number": 22}]}]}}
    entry = jit_policy_merge.build_vm_entry("/vm/x", [3389])
    merged = jit_policy_merge.merge_policy(existing, entry)
    vms = merged["properties"]["virtualMachines"]
    assert len(vms) == 1
    assert vms[0]["id"] == "/vm/x"
    assert [port["number"] for port in vms[0]["ports"]] == [3389]


def test_merge_creates_policy_when_none_exists():
    """With no existing policy, a fresh Basic policy containing just this VM is produced."""
    merged = jit_policy_merge.merge_policy(None, jit_policy_merge.build_vm_entry("/vm/a", [22]))
    assert merged["kind"] == "Basic"
    assert [vm["id"] for vm in merged["properties"]["virtualMachines"]] == ["/vm/a"]


def test_build_vm_entry_shape():
    entry = jit_policy_merge.build_vm_entry("/vm/a", [22, 3389])
    assert entry["id"] == "/vm/a"
    assert [port["number"] for port in entry["ports"]] == [22, 3389]
    assert all(port["maxRequestAccessDuration"] == "PT3H" for port in entry["ports"])
