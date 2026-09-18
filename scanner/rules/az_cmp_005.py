"""AZ-CMP-005: Generation 2 VM without Trusted Launch (Secure Boot and vTPM) enabled."""

import logging
from typing import Any, Dict, List, Optional

RULE_ID = "AZ-CMP-005"
RULE_NAME = "VM Without Trusted Launch (Secure Boot and vTPM) Enabled"
SEVERITY = "MEDIUM"
CATEGORY = "Compute"
FRAMEWORKS = {
    "CIS": "N/A-CMP-005",
    "NIST": "PR.DS-6",
    "ISO27001": "A.12.5.1",
    "SOC2": "CC6.8",
}
DESCRIPTION = (
    "A Generation 2 virtual machine does not have Trusted Launch fully enabled "
    "(security type TrustedLaunch with both Secure Boot and vTPM turned on). "
    "Without Secure Boot and a virtual TPM, unsigned or malicious code can run "
    "during boot and persist beneath the OS, evading OS-level antimalware and EDR. "
    "Generation 1 VMs do not support Trusted Launch and are not flagged."
)
REMEDIATION = (
    "Enable Trusted Launch on the VM: set the security type to TrustedLaunch and "
    "turn on Secure Boot and vTPM, e.g. `az vm update --name <vm> "
    "--resource-group <rg> --security-type TrustedLaunch --enable-secure-boot true "
    "--enable-vtpm true` (requires a restart; only supported on Gen2 VM sizes/images)."
)
PLAYBOOK = "playbooks/cli/fix_az_cmp_005.sh"

logger = logging.getLogger(__name__)

_TRUSTED_LAUNCH = "TrustedLaunch"
_CONFIDENTIAL_VM = "ConfidentialVM"


def _trusted_launch_fully_enabled(security_profile: Any) -> bool:
    """True only when security type is TrustedLaunch and Secure Boot and vTPM are both on."""
    if security_profile is None:
        return False
    if getattr(security_profile, "security_type", None) != _TRUSTED_LAUNCH:
        return False
    uefi = getattr(security_profile, "uefi_settings", None)
    if uefi is None:
        return False
    return getattr(uefi, "secure_boot_enabled", None) is True and getattr(uefi, "v_tpm_enabled", None) is True


def _os_disk_generation(azure_client: Any, vm: Any) -> Optional[str]:
    """Resolve the VM's OS-disk Hyper-V generation ('V1'/'V2'), or None if undeterminable.

    A VM's list_all() representation does not carry its Hyper-V generation, but the
    underlying managed OS disk does. Returns None when the disk id is missing or the
    Disk resource cannot be read (permissions/deletion); callers must treat None as
    'generation unknown', never as Gen2.
    """
    storage_profile = getattr(vm, "storage_profile", None)
    os_disk = getattr(storage_profile, "os_disk", None) if storage_profile else None
    managed_disk = getattr(os_disk, "managed_disk", None) if os_disk else None
    disk_id = getattr(managed_disk, "id", "") if managed_disk else ""
    if not disk_id:
        return None
    disk = azure_client.get_disk(disk_id)
    if disk is None:
        return None
    return getattr(disk, "hyper_v_generation", None) or None


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Flag Generation 2 VMs that do not have Trusted Launch fully enabled.

    Generation 1 VMs (which cannot use Trusted Launch) and VMs whose generation
    cannot be confirmed as Gen2 are treated as NOT_APPLICABLE and are not flagged,
    so the rule never raises a false finding against hardware that could not satisfy
    it. A readable Gen1 OS disk reports 'V1'; only a confirmed 'V2' (or a security
    type already declared as TrustedLaunch, which is itself Gen2-only) is flagged.
    """
    findings: List[Dict[str, Any]] = []

    for vm in azure_client.get_virtual_machines():
        security_profile = getattr(vm, "security_profile", None)

        if _trusted_launch_fully_enabled(security_profile):
            continue  # compliant

        security_type = getattr(security_profile, "security_type", None) if security_profile else None
        if security_type == _CONFIDENTIAL_VM:
            # Confidential VMs provide Secure Boot and vTPM by construction; out of scope.
            continue

        if security_type == _TRUSTED_LAUNCH:
            # Security type is TrustedLaunch (hence definitely Gen2) but Secure Boot
            # and/or vTPM is not on — a real, confirmable misconfiguration, no disk
            # lookup needed.
            generation: Optional[str] = "V2"
        else:
            generation = _os_disk_generation(azure_client, vm)
            if generation != "V2":
                # Gen1 (NOT_APPLICABLE) or generation unknown — do not raise a finding.
                continue

        uefi = getattr(security_profile, "uefi_settings", None) if security_profile else None
        parsed = azure_client.parse_resource_id(getattr(vm, "id", ""))
        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": getattr(vm, "id", ""),
                "resource_name": getattr(vm, "name", None) or parsed.get("name", ""),
                "resource_type": "Microsoft.Compute/virtualMachines",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "security_type": security_type or "None",
                    "secure_boot_enabled": getattr(uefi, "secure_boot_enabled", None) if uefi else None,
                    "v_tpm_enabled": getattr(uefi, "v_tpm_enabled", None) if uefi else None,
                    "hyper_v_generation": generation,
                },
            }
        )

    return findings
