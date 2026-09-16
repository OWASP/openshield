"""Rule regression tests for the compute rules AZ-CMP-001 .. AZ-CMP-004.

Each test configures a MockAzureClient with fake VM/NIC/extension data and
calls the rule's scan() function directly. No network calls are made — the
mock_azure and subscription_id fixtures come from tests/conftest.py and the
helper accessors from tests/helpers/mock_azure.py.
"""

import pytest

import scanner.rules.az_cmp_001 as az_cmp_001
import scanner.rules.az_cmp_002 as az_cmp_002
import scanner.rules.az_cmp_003 as az_cmp_003
import scanner.rules.az_cmp_004 as az_cmp_004
import scanner.rules.az_cmp_007 as az_cmp_007
from tests.helpers.mock_azure import make_resource

try:
    from azure.mgmt.compute.models import Disk, Encryption, EncryptionSettingsCollection, ManagedDiskParameters

    _AZURE_SDK_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when SDK isn't installed
    _AZURE_SDK_AVAILABLE = False

_REQUIRED_FIELDS = {
    "rule_id",
    "rule_name",
    "severity",
    "category",
    "resource_id",
    "resource_name",
    "resource_type",
    "description",
    "remediation",
    "playbook",
    "frameworks",
}

_SUB = "00000000-0000-0000-0000-000000000001"
_RG = "rg-test"


def _vm_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.Compute/virtualMachines/{name}"


def _nic_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.Network/networkInterfaces/{name}"


def _disk_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.Compute/disks/{name}"


# ── AZ-CMP-001: VM public IP with no NSG ────────────────────────────────────


def test_cmp_001_compliant_nic_with_nsg_returns_no_findings(mock_azure, subscription_id):
    """A NIC with a public IP but a protecting NSG is compliant."""
    nic = make_resource(
        ip_configurations=[make_resource(public_ip_address=make_resource(id="pip1"))],
        network_security_group=make_resource(id="nsg1"),
    )
    vm = make_resource(
        id=_vm_id("vm-compliant"),
        name="vm-compliant",
        network_profile=make_resource(network_interfaces=[make_resource(id=_nic_id("nic1"))]),
    )
    mock_azure.set_virtual_machines([vm])
    mock_azure.set_network_interface(_RG, "nic1", nic)
    assert az_cmp_001.scan(mock_azure, subscription_id) == []


def test_cmp_001_noncompliant_public_ip_no_nsg_returns_one_finding(mock_azure, subscription_id):
    """A NIC with a public IP and no NSG must produce exactly one finding."""
    nic = make_resource(
        ip_configurations=[make_resource(public_ip_address=make_resource(id="pip1"))],
        network_security_group=None,
    )
    vm = make_resource(
        id=_vm_id("vm-exposed"),
        name="vm-exposed",
        network_profile=make_resource(network_interfaces=[make_resource(id=_nic_id("nic1"))]),
    )
    mock_azure.set_virtual_machines([vm])
    mock_azure.set_network_interface(_RG, "nic1", nic)
    findings = az_cmp_001.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    f = findings[0]
    assert _REQUIRED_FIELDS.issubset(f.keys())
    assert f["rule_id"] == "AZ-CMP-001"
    assert f["severity"] == "HIGH"
    assert f["resource_name"] == "vm-exposed"


# ── AZ-CMP-002: disk using platform-managed encryption only ─────────────────
#
# ManagedDiskParameters (the object actually embedded in a VM's
# storage_profile.os_disk/data_disks) only exposes id, storage_account_type,
# disk_encryption_set and security_profile -- it has no "encryption"
# attribute, and its security_profile (VMDiskSecurityProfile) carries
# security_encryption_type, not "type". The real encryption state lives on
# the underlying Disk resource, resolved via AzureClient.get_disk(id), whose
# Encryption.type and EncryptionSettingsCollection.enabled are the fields
# that actually distinguish compliant from non-compliant. These fixtures
# mirror that shape instead of inventing attributes the SDK does not define.


def _managed_disk(name):
    """A ManagedDiskParameters-shaped stub: only carries an id."""
    return make_resource(id=_disk_id(name))


def _disk(encryption_type=None, ade_enabled=False):
    """A Disk-shaped stub as returned by AzureClient.get_disk()."""
    return make_resource(
        encryption=make_resource(type=encryption_type) if encryption_type else None,
        encryption_settings_collection=make_resource(enabled=ade_enabled),
    )


def test_cmp_002_compliant_customer_key_returns_no_findings(mock_azure, subscription_id):
    """OS disk encrypted with a customer-managed key only is compliant."""
    os_disk = make_resource(name="osdisk", managed_disk=_managed_disk("disk-cmk"))
    vm = make_resource(
        id=_vm_id("vm-cmk"),
        name="vm-cmk",
        location="eastus",
        storage_profile=make_resource(os_disk=os_disk, data_disks=[]),
    )
    mock_azure.set_virtual_machines([vm])
    mock_azure.set_disk(_disk_id("disk-cmk"), _disk(encryption_type="EncryptionAtRestWithCustomerKey"))
    assert az_cmp_002.scan(mock_azure, subscription_id) == []


def test_cmp_002_compliant_platform_and_customer_key_returns_no_findings(mock_azure, subscription_id):
    """OS disk encrypted with platform-and-customer keys is compliant."""
    os_disk = make_resource(name="osdisk", managed_disk=_managed_disk("disk-both"))
    vm = make_resource(
        id=_vm_id("vm-both"),
        name="vm-both",
        location="eastus",
        storage_profile=make_resource(os_disk=os_disk, data_disks=[]),
    )
    mock_azure.set_virtual_machines([vm])
    mock_azure.set_disk(_disk_id("disk-both"), _disk(encryption_type="EncryptionAtRestWithPlatformAndCustomerKeys"))
    assert az_cmp_002.scan(mock_azure, subscription_id) == []


def test_cmp_002_compliant_ade_enabled_returns_no_findings(mock_azure, subscription_id):
    """A platform-key disk with Azure Disk Encryption enabled is compliant."""
    os_disk = make_resource(name="osdisk", managed_disk=_managed_disk("disk-ade"))
    vm = make_resource(
        id=_vm_id("vm-ade"),
        name="vm-ade",
        location="eastus",
        storage_profile=make_resource(os_disk=os_disk, data_disks=[]),
    )
    mock_azure.set_virtual_machines([vm])
    mock_azure.set_disk(
        _disk_id("disk-ade"), _disk(encryption_type="EncryptionAtRestWithPlatformKey", ade_enabled=True)
    )
    assert az_cmp_002.scan(mock_azure, subscription_id) == []


def test_cmp_002_noncompliant_platform_key_returns_one_finding(mock_azure, subscription_id):
    """OS disk using platform-managed encryption only, with no ADE, must be flagged.

    This is a regression test: the previous implementation read
    managed_disk.security_profile / managed_disk.encryption, neither of
    which exist on ManagedDiskParameters, so every branch resolved to None
    and this case incorrectly returned no findings.
    """
    os_disk = make_resource(name="osdisk", managed_disk=_managed_disk("disk-pmk"))
    vm = make_resource(
        id=_vm_id("vm-pmk"),
        name="vm-pmk",
        location="eastus",
        storage_profile=make_resource(os_disk=os_disk, data_disks=[]),
    )
    mock_azure.set_virtual_machines([vm])
    mock_azure.set_disk(_disk_id("disk-pmk"), _disk(encryption_type="EncryptionAtRestWithPlatformKey"))
    findings = az_cmp_002.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    f = findings[0]
    assert _REQUIRED_FIELDS.issubset(f.keys())
    assert f["rule_id"] == "AZ-CMP-002"
    assert f["severity"] == "HIGH"
    assert f["resource_name"] == "vm-pmk"
    assert f["metadata"]["unencrypted_disks"] == ["osdisk"]
    assert f["metadata"]["indeterminate_disks"] == []
    assert f["metadata"]["determination"] == "non_compliant"


def test_cmp_002_indeterminate_unreadable_disk_returns_low_severity_unknown_finding(mock_azure, subscription_id):
    """A Disk resource that cannot be read must not be treated as compliant, but it is
    also not a confirmed violation, so it must not carry the same HIGH severity as an
    actual platform-key-only disk — it surfaces as a distinct, lower-severity unknown
    scan result instead."""
    os_disk = make_resource(name="osdisk", managed_disk=_managed_disk("disk-unreadable"))
    vm = make_resource(
        id=_vm_id("vm-unreadable"),
        name="vm-unreadable",
        location="eastus",
        storage_profile=make_resource(os_disk=os_disk, data_disks=[]),
    )
    mock_azure.set_virtual_machines([vm])
    # No mock_azure.set_disk() call: get_disk() returns None, as it would if
    # Azure denied access or the disk had been deleted.
    findings = az_cmp_002.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "LOW"
    assert f["metadata"]["unencrypted_disks"] == []
    assert f["metadata"]["indeterminate_disks"] == ["osdisk"]
    assert f["metadata"]["determination"] == "indeterminate"


def test_cmp_002_confirmed_violation_outweighs_indeterminate_sibling_disk(mock_azure, subscription_id):
    """A VM with one confirmed platform-key-only disk and one unreadable disk is a real
    HIGH finding, not an unknown one — the confirmed violation must not be diluted by an
    indeterminate sibling on the same VM."""
    os_disk = make_resource(name="osdisk", managed_disk=_managed_disk("disk-pmk-2"))
    data_disk = make_resource(name="datadisk", lun=0, managed_disk=_managed_disk("disk-unreadable-2"))
    vm = make_resource(
        id=_vm_id("vm-mixed"),
        name="vm-mixed",
        location="eastus",
        storage_profile=make_resource(os_disk=os_disk, data_disks=[data_disk]),
    )
    mock_azure.set_virtual_machines([vm])
    mock_azure.set_disk(_disk_id("disk-pmk-2"), _disk(encryption_type="EncryptionAtRestWithPlatformKey"))
    # disk-unreadable-2 is left unconfigured on the mock: get_disk() returns None.
    findings = az_cmp_002.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "HIGH"
    assert f["metadata"]["unencrypted_disks"] == ["osdisk"]
    assert f["metadata"]["indeterminate_disks"] == ["datadisk"]
    assert f["metadata"]["determination"] == "non_compliant"


@pytest.mark.skipif(not _AZURE_SDK_AVAILABLE, reason="azure-mgmt-compute not installed")
def test_cmp_002_managed_disk_parameters_has_no_encryption_attribute():
    """SDK-shape guard: the original bug read managed_disk.encryption /
    managed_disk.security_profile.type, attributes ManagedDiskParameters has never
    exposed. If a future SDK bump ever added them, this rule's real-model tests below
    would silently stop testing anything — this test fails loudly instead if the SDK's
    actual attribute surface ever drifts from what the fix assumes."""
    managed_disk = ManagedDiskParameters(id="disk-1")
    assert not hasattr(managed_disk, "encryption")


@pytest.mark.skipif(not _AZURE_SDK_AVAILABLE, reason="azure-mgmt-compute not installed")
def test_cmp_002_noncompliant_with_real_sdk_models_returns_one_finding(mock_azure, subscription_id):
    """Regression test using genuine azure.mgmt.compute.models instances (not
    make_resource stand-ins, which accept arbitrary kwargs and would have silently
    accepted the original bug's invented attribute shape). ManagedDiskParameters only
    carries an id; Disk.encryption.type is the real source of truth for the platform-key
    determination."""
    managed_disk = ManagedDiskParameters(id=_disk_id("disk-pmk-real"))
    os_disk = make_resource(name="osdisk", managed_disk=managed_disk)
    vm = make_resource(
        id=_vm_id("vm-pmk-real"),
        name="vm-pmk-real",
        location="eastus",
        storage_profile=make_resource(os_disk=os_disk, data_disks=[]),
    )
    mock_azure.set_virtual_machines([vm])
    real_disk = Disk(
        location="eastus",
        encryption=Encryption(type="EncryptionAtRestWithPlatformKey"),
        encryption_settings_collection=EncryptionSettingsCollection(enabled=False),
    )
    mock_azure.set_disk(_disk_id("disk-pmk-real"), real_disk)

    findings = az_cmp_002.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "HIGH"
    assert f["metadata"]["unencrypted_disks"] == ["osdisk"]
    assert f["metadata"]["determination"] == "non_compliant"


@pytest.mark.skipif(not _AZURE_SDK_AVAILABLE, reason="azure-mgmt-compute not installed")
def test_cmp_002_compliant_with_real_sdk_models_returns_no_findings(mock_azure, subscription_id):
    """Real SDK model counterpart: a customer-managed key disk (genuine Disk/Encryption
    instances) must not be flagged."""
    managed_disk = ManagedDiskParameters(id=_disk_id("disk-cmk-real"))
    os_disk = make_resource(name="osdisk", managed_disk=managed_disk)
    vm = make_resource(
        id=_vm_id("vm-cmk-real"),
        name="vm-cmk-real",
        location="eastus",
        storage_profile=make_resource(os_disk=os_disk, data_disks=[]),
    )
    mock_azure.set_virtual_machines([vm])
    real_disk = Disk(
        location="eastus",
        encryption=Encryption(type="EncryptionAtRestWithCustomerKey"),
        encryption_settings_collection=EncryptionSettingsCollection(enabled=False),
    )
    mock_azure.set_disk(_disk_id("disk-cmk-real"), real_disk)

    assert az_cmp_002.scan(mock_azure, subscription_id) == []


# ── AZ-CMP-003: VM without endpoint protection ──────────────────────────────


def test_cmp_003_compliant_with_ep_extension_returns_no_findings(mock_azure, subscription_id):
    """A VM with a recognised endpoint-protection extension is compliant."""
    vm = make_resource(id=_vm_id("vm-protected"), name="vm-protected")
    mock_azure.set_virtual_machines([vm])
    mock_azure.set_vm_extensions(
        _RG,
        "vm-protected",
        [make_resource(type_properties_type="IaaSAntimalware")],
    )
    assert az_cmp_003.scan(mock_azure, subscription_id) == []


def test_cmp_003_noncompliant_no_ep_extension_returns_one_finding(mock_azure, subscription_id):
    """A VM with no endpoint-protection extension must produce one finding."""
    vm = make_resource(id=_vm_id("vm-unprotected"), name="vm-unprotected")
    mock_azure.set_virtual_machines([vm])
    mock_azure.set_vm_extensions(
        _RG,
        "vm-unprotected",
        [make_resource(type_properties_type="CustomScript")],
    )
    findings = az_cmp_003.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    f = findings[0]
    assert _REQUIRED_FIELDS.issubset(f.keys())
    assert f["rule_id"] == "AZ-CMP-003"
    assert f["severity"] == "HIGH"
    assert f["resource_name"] == "vm-unprotected"


def test_cmp_003_extensions_none_skips_without_finding(mock_azure, subscription_id):
    """When extensions cannot be determined (None) the rule must not flag."""
    vm = make_resource(id=_vm_id("vm-unknown"), name="vm-unknown")
    mock_azure.set_virtual_machines([vm])
    mock_azure.set_vm_extensions(_RG, "vm-unknown", None)
    assert az_cmp_003.scan(mock_azure, subscription_id) == []


# ── AZ-CMP-004: VM without automatic OS patching ────────────────────────────


def test_cmp_004_compliant_auto_updates_returns_no_findings(mock_azure, subscription_id):
    """A Windows VM with automatic updates enabled is compliant."""
    vm = make_resource(
        id=_vm_id("vm-patched"),
        name="vm-patched",
        os_profile=make_resource(
            windows_configuration=make_resource(enable_automatic_updates=True, patch_settings=None),
            linux_configuration=None,
        ),
    )
    mock_azure.set_virtual_machines([vm])
    assert az_cmp_004.scan(mock_azure, subscription_id) == []


def test_cmp_004_noncompliant_no_patching_returns_one_finding(mock_azure, subscription_id):
    """A Windows VM with auto-updates off and no auto patch-mode must flag."""
    vm = make_resource(
        id=_vm_id("vm-stale"),
        name="vm-stale",
        os_profile=make_resource(
            windows_configuration=make_resource(enable_automatic_updates=False, patch_settings=None),
            linux_configuration=None,
        ),
    )
    mock_azure.set_virtual_machines([vm])
    findings = az_cmp_004.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    f = findings[0]
    assert _REQUIRED_FIELDS.issubset(f.keys())
    assert f["rule_id"] == "AZ-CMP-004"
    assert f["severity"] == "HIGH"
    assert f["resource_name"] == "vm-stale"


# ── AZ-CMP-007: management ports open without Just-In-Time (JIT) access ──────
#
# The rule resolves each VM's NIC -> NSG (by id, via get_network_security_groups)
# to find management ports (22/3389) open to the internet, then cross-references
# Defender for Cloud JIT policies (get_jit_network_access_policies) to see whether
# those ports are covered. These fixtures mirror that wiring.


def _nsg_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.Network/networkSecurityGroups/{name}"


def _sec_rule(port, direction="Inbound", access="Allow", source="Internet"):
    return make_resource(
        direction=direction,
        access=access,
        source_address_prefix=source,
        source_address_prefixes=[],
        destination_port_range=str(port),
        destination_port_ranges=[],
    )


def _nsg(name, rules):
    return make_resource(id=_nsg_id(name), name=name, security_rules=rules)


def _vm_on_nic(vm_name, nic_name):
    return make_resource(
        id=_vm_id(vm_name),
        name=vm_name,
        network_profile=make_resource(network_interfaces=[make_resource(id=_nic_id(nic_name))]),
    )


def _nic_on_nsg(nsg_name):
    return make_resource(network_security_group=make_resource(id=_nsg_id(nsg_name)))


def _jit_policy(vm_name, ports):
    return make_resource(
        virtual_machines=[make_resource(id=_vm_id(vm_name), ports=[make_resource(number=p) for p in ports])]
    )


def _wire(mock_azure, vm, nic_name, nic, nsg, jit):
    mock_azure.set_virtual_machines([vm])
    mock_azure.set_network_interface(_RG, nic_name, nic)
    mock_azure.set_network_security_groups([nsg])
    mock_azure.set_jit_policies(jit)


def test_cmp_007_open_ssh_no_jit_returns_one_finding(mock_azure, subscription_id):
    """SSH open to the internet with no JIT policy must be flagged MEDIUM."""
    _wire(
        mock_azure,
        _vm_on_nic("vm-open", "nic1"),
        "nic1",
        _nic_on_nsg("nsg1"),
        _nsg("nsg1", [_sec_rule("22")]),
        [],
    )
    findings = az_cmp_007.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    f = findings[0]
    assert _REQUIRED_FIELDS.issubset(f.keys())
    assert f["rule_id"] == "AZ-CMP-007"
    assert f["severity"] == "MEDIUM"
    assert f["resource_name"] == "vm-open"
    assert f["metadata"]["open_management_ports"] == ["22"]
    assert f["metadata"]["uncovered_ports"] == ["22"]
    assert f["metadata"]["jit_policy_present"] is False


def test_cmp_007_open_ssh_with_jit_coverage_returns_no_findings(mock_azure, subscription_id):
    """An open SSH port covered by a JIT policy for that VM is compliant."""
    _wire(
        mock_azure,
        _vm_on_nic("vm-jit", "nic1"),
        "nic1",
        _nic_on_nsg("nsg1"),
        _nsg("nsg1", [_sec_rule("22")]),
        [_jit_policy("vm-jit", [22])],
    )
    assert az_cmp_007.scan(mock_azure, subscription_id) == []


def test_cmp_007_no_management_ports_open_is_not_applicable(mock_azure, subscription_id):
    """A VM whose NSG opens only non-management ports is NOT_APPLICABLE."""
    _wire(
        mock_azure,
        _vm_on_nic("vm-web", "nic1"),
        "nic1",
        _nic_on_nsg("nsg1"),
        _nsg("nsg1", [_sec_rule("443")]),
        [],
    )
    assert az_cmp_007.scan(mock_azure, subscription_id) == []


def test_cmp_007_management_port_from_trusted_source_not_flagged(mock_azure, subscription_id):
    """RDP open only to a trusted CIDR (not the internet) must not be flagged."""
    _wire(
        mock_azure,
        _vm_on_nic("vm-trusted", "nic1"),
        "nic1",
        _nic_on_nsg("nsg1"),
        _nsg("nsg1", [_sec_rule("3389", source="10.0.0.0/24")]),
        [],
    )
    assert az_cmp_007.scan(mock_azure, subscription_id) == []


def test_cmp_007_partial_jit_coverage_flags_uncovered_port(mock_azure, subscription_id):
    """When JIT covers SSH but RDP is also open, only the uncovered RDP port is reported."""
    _wire(
        mock_azure,
        _vm_on_nic("vm-partial", "nic1"),
        "nic1",
        _nic_on_nsg("nsg1"),
        _nsg("nsg1", [_sec_rule("22"), _sec_rule("3389")]),
        [_jit_policy("vm-partial", [22])],
    )
    findings = az_cmp_007.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["open_management_ports"] == ["22", "3389"]
    assert findings[0]["metadata"]["uncovered_ports"] == ["3389"]
    assert findings[0]["metadata"]["jit_policy_present"] is True


def test_cmp_007_indeterminate_jit_is_not_flagged(mock_azure, subscription_id):
    """When Defender for Cloud cannot be queried (None), coverage is unknown, so no finding."""
    _wire(
        mock_azure,
        _vm_on_nic("vm-x", "nic1"),
        "nic1",
        _nic_on_nsg("nsg1"),
        _nsg("nsg1", [_sec_rule("3389")]),
        None,
    )
    assert az_cmp_007.scan(mock_azure, subscription_id) == []


def _subnet_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.Network/virtualNetworks/vnet/subnets/{name}"


def test_cmp_007_port_range_covering_ssh_is_flagged(mock_azure, subscription_id):
    """An NSG rule whose destination_port_range is a range (20-30) containing SSH (22)
    exposes the port; the earlier exact-match logic treated 22 as closed."""
    _wire(
        mock_azure,
        _vm_on_nic("vm-range", "nic1"),
        "nic1",
        _nic_on_nsg("nsg1"),
        _nsg("nsg1", [_sec_rule("20-30")]),
        [],
    )
    findings = az_cmp_007.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["open_management_ports"] == ["22"]


def test_cmp_007_port_range_in_ranges_list_covering_rdp(mock_azure, subscription_id):
    """A range in destination_port_ranges (3380-3400) containing RDP (3389) is detected."""
    rule = make_resource(
        direction="Inbound",
        access="Allow",
        source_address_prefix="Internet",
        source_address_prefixes=[],
        destination_port_range="",
        destination_port_ranges=["3380-3400"],
    )
    _wire(
        mock_azure,
        _vm_on_nic("vm-range2", "nic1"),
        "nic1",
        _nic_on_nsg("nsg1"),
        _nsg("nsg1", [rule]),
        [],
    )
    findings = az_cmp_007.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["open_management_ports"] == ["3389"]


def test_cmp_007_subnet_level_nsg_exposure_is_flagged(mock_azure, subscription_id):
    """A VM with no NIC-level NSG is still exposed if the NSG on its subnet opens SSH."""
    subnet_id = _subnet_id("subnet1")
    nic = make_resource(
        network_security_group=None,
        ip_configurations=[make_resource(subnet=make_resource(id=subnet_id))],
    )
    subnet_nsg = make_resource(
        id=_nsg_id("nsg-sub"),
        name="nsg-sub",
        security_rules=[_sec_rule("22")],
        subnets=[make_resource(id=subnet_id)],
    )
    _wire(mock_azure, _vm_on_nic("vm-subnet", "nic1"), "nic1", nic, subnet_nsg, [])
    findings = az_cmp_007.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["resource_name"] == "vm-subnet"
    assert findings[0]["metadata"]["open_management_ports"] == ["22"]
