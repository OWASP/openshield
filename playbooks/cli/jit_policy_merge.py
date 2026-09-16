#!/usr/bin/env python3
"""Merge one VM's JIT entry into an existing Defender for Cloud JIT policy.

The Defender for Cloud ``jitNetworkAccessPolicies`` PUT is a *create-or-update*
that replaces the whole ``properties.virtualMachines`` array. Sending a policy
that contains only the VM being remediated would therefore drop JIT coverage for
every other VM already in the shared ``default`` policy.

This helper reads the current policy JSON from stdin (empty/whitespace means the
policy does not exist yet) and prints the full policy to PUT, preserving every
other VM's entry and replacing (not duplicating) the target VM's own entry.

Usage:
    az rest --method GET ... | jit_policy_merge.py <vm-id> <port> [<port> ...]
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List

_DEFAULT_MAX_DURATION = "PT3H"


def build_vm_entry(vm_id: str, ports: List[int]) -> Dict[str, Any]:
    return {
        "id": vm_id,
        "ports": [
            {
                "number": port,
                "protocol": "*",
                "allowedSourceAddressPrefix": "*",
                "maxRequestAccessDuration": _DEFAULT_MAX_DURATION,
            }
            for port in ports
        ],
    }


def merge_policy(existing: Dict[str, Any] | None, vm_entry: Dict[str, Any]) -> Dict[str, Any]:
    """Return a policy that keeps every other VM and (re)sets the target VM's entry."""
    if existing and isinstance(existing.get("properties"), dict):
        policy = existing
    else:
        policy = {"kind": "Basic", "properties": {}}
    properties = policy.setdefault("properties", {})
    others = [
        vm
        for vm in (properties.get("virtualMachines") or [])
        if isinstance(vm, dict) and vm.get("id") != vm_entry["id"]
    ]
    properties["virtualMachines"] = others + [vm_entry]
    return policy


def main(argv: List[str]) -> int:
    if len(argv) < 3:
        print(f"usage: {argv[0]} <vm-id> <port> [<port> ...]", file=sys.stderr)
        return 2
    vm_id = argv[1]
    ports = [int(port) for port in argv[2:]]
    raw = sys.stdin.read().strip()
    existing = json.loads(raw) if raw else None
    print(json.dumps(merge_policy(existing, build_vm_entry(vm_id, ports))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
