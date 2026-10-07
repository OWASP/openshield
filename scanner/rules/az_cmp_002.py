"""AZ-CMP-002: Virtual machine OS or data disk using platform-managed encryption only."""

import logging
from typing import Any, Dict, List, Optional

from scanner.azure_client import enum_str

RULE_ID = "AZ-CMP-002"
RULE_NAME = "Virtual machine disk not protected by customer-managed key or ADE"
SEVERITY = "HIGH"
CATEGORY = "Compute"
FRAMEWORKS = {"CIS": "7.2", "NIST": "PR.DS-1", "ISO27001": "A.8.24", "SOC2": "CC6.7"}
DESCRIPTION = (
    "One or more disks attached to this virtual machine are using platform-managed "
    "encryption only (EncryptionAtRestWithPlatformKey). CIS 7.2 requires disks to be "
    "protected using either Azure Disk Encryption (ADE) or server-side encryption with "
    "a customer-managed key (CMK). Platform-managed encryption does not give the "
    "organisation control over the encryption keys."
)
REMEDIATION = (
    "Configure server-side encryption with a customer-managed key via a Disk Encryption "
    "Set, or enable Azure Disk Encryption on all OS and data disks. Navigate to: "
    "Virtual Machine > Disks > Additional settings > Disk encryption set, or use "
    "az vm encryption enable with a Key Vault."
)
PLAYBOOK = "playbooks/cli/fix_az_cmp_002.sh"

# Unreadable disks are reported as an unknown scan result, not a confirmed
# violation: a missing Microsoft.Compute/disks/read grant says nothing about
# the disk's actual encryption state, so it must not carry HIGH severity or
# the standard remediation (which could send someone to re-encrypt a disk
# that was already compliant via CMK).
INDETERMINATE_SEVERITY = "LOW"
INDETERMINATE_DESCRIPTION = (
    "One or more disks attached to this virtual machine could not be read, so their "
    "encryption configuration could not be verified against CIS 7.2. This is not a "
    "confirmed violation — the scanning principal could not resolve the Disk resource "
    "(missing Microsoft.Compute/disks/read, transient API failure, or the disk no "
    "longer exists)."
)
INDETERMINATE_REMEDIATION = (
    "Grant the scanning principal Microsoft.Compute/disks/read on the affected disk(s) "
    "and re-run the scan to determine the actual encryption state."
)

logger = logging.getLogger(__name__)

_PLATFORM_KEY_ONLY = "EncryptionAtRestWithPlatformKey"
_CUSTOMER_MANAGED_TYPES = {
    "EncryptionAtRestWithCustomerKey",
    "EncryptionAtRestWithPlatformAndCustomerKeys",
}


def _classify_disk(azure_client: Any, managed_disk: Any) -> Optional[str]:
    """Classify a VM's managed disk as "compliant", "non_compliant", or "indeterminate".

    Returns None when there is no managed disk to evaluate at all (e.g. an
    ephemeral OS disk with no managed disk reference) — that is not the same
    as an indeterminate result and must not be surfaced as either a pass or
    a finding.

    A VM's storage_profile only embeds a ManagedDiskParameters reference
    (id, storage_account_type, disk_encryption_set, security_profile) — the
    encryption state lives on the underlying Disk resource and must be
    resolved via AzureClient.get_disk(). Azure Disk Encryption (ADE) is
    reported on Disk.encryption_settings_collection.enabled and satisfies
    CIS 7.2 regardless of the key type. Absent ADE, Disk.encryption.type
    distinguishes EncryptionAtRestWithPlatformKey (non-compliant) from
    EncryptionAtRestWithCustomerKey / EncryptionAtRestWithPlatformAndCustomerKeys
    (compliant).
    """
    if managed_disk is None:
        return None

    disk_id = getattr(managed_disk, "id", None)
    if not disk_id:
        logger.warning("AZ-CMP-002: managed disk has no id, marking indeterminate")
        return "indeterminate"

    disk = azure_client.get_disk(disk_id)
    if disk is None:
        logger.warning("AZ-CMP-002: could not resolve Disk resource %s, marking indeterminate", disk_id)
        return "indeterminate"

    ade_settings = getattr(disk, "encryption_settings_collection", None)
    if getattr(ade_settings, "enabled", False):
        return "compliant"

    encryption = getattr(disk, "encryption", None)
    encryption_type = enum_str(getattr(encryption, "type", None))

    if encryption_type == _PLATFORM_KEY_ONLY:
        return "non_compliant"
    if encryption_type in _CUSTOMER_MANAGED_TYPES:
        return "compliant"

    logger.warning(
        "AZ-CMP-002: disk %s has unrecognised encryption type %r, marking indeterminate",
        disk_id,
        encryption_type,
    )
    return "indeterminate"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect virtual machines whose disks use platform-managed encryption only."""
    findings: List[Dict[str, Any]] = []

    for vm in azure_client.get_virtual_machines():
        vm_id = getattr(vm, "id", "")
        vm_name = getattr(vm, "name", "")
        location = getattr(vm, "location", "")

        if not vm_id or not vm_name:
            continue

        parsed = azure_client.parse_resource_id(vm_id)
        resource_group = parsed.get("resource_group", "")

        storage_profile = getattr(vm, "storage_profile", None)
        if not storage_profile:
            continue

        unencrypted_disks = []
        indeterminate_disks = []

        # Check OS disk
        os_disk = getattr(storage_profile, "os_disk", None)
        if os_disk:
            managed_disk = getattr(os_disk, "managed_disk", None)
            status = _classify_disk(azure_client, managed_disk)
            disk_name = getattr(os_disk, "name", "os-disk")
            if status == "non_compliant":
                unencrypted_disks.append(disk_name)
            elif status == "indeterminate":
                indeterminate_disks.append(disk_name)

        # Check data disks
        data_disks = getattr(storage_profile, "data_disks", []) or []
        for disk in data_disks:
            managed_disk = getattr(disk, "managed_disk", None)
            status = _classify_disk(azure_client, managed_disk)
            disk_name = getattr(disk, "name", f"data-disk-{getattr(disk, 'lun', '?')}")
            if status == "non_compliant":
                unencrypted_disks.append(disk_name)
            elif status == "indeterminate":
                indeterminate_disks.append(disk_name)

        if unencrypted_disks or indeterminate_disks:
            # A confirmed non-compliant disk makes the whole finding a real
            # HIGH violation, even if other disks on the same VM are also
            # indeterminate. Only when *nothing* is confirmed non-compliant
            # does this drop to an unknown/LOW scan result.
            confirmed = bool(unencrypted_disks)
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY if confirmed else INDETERMINATE_SEVERITY,
                    "category": CATEGORY,
                    "resource_id": vm_id,
                    "resource_name": vm_name,
                    "resource_type": "Microsoft.Compute/virtualMachines",
                    "description": DESCRIPTION if confirmed else INDETERMINATE_DESCRIPTION,
                    "remediation": REMEDIATION if confirmed else INDETERMINATE_REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "resource_group": resource_group,
                        "location": location,
                        "unencrypted_disks": unencrypted_disks,
                        "unencrypted_disk_count": len(unencrypted_disks),
                        "indeterminate_disks": indeterminate_disks,
                        "indeterminate_disk_count": len(indeterminate_disks),
                        "determination": "non_compliant" if confirmed else "indeterminate",
                    },
                }
            )

    return findings
