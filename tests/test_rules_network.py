"""Rule regression tests for the network rules AZ-NET-001 .. AZ-NET-017.

AZ-NET-007/009/010 construct a NetworkManagementClient inside scan(); those
tests monkeypatch azure.mgmt.network.NetworkManagementClient. The rest read data
through MockAzureClient accessors. No real network calls are made.
"""

from types import SimpleNamespace

import pytest

import scanner.rules.az_net_001 as az_net_001
import scanner.rules.az_net_002 as az_net_002
import scanner.rules.az_net_003 as az_net_003
import scanner.rules.az_net_004 as az_net_004
import scanner.rules.az_net_005 as az_net_005
import scanner.rules.az_net_006 as az_net_006
import scanner.rules.az_net_007 as az_net_007
import scanner.rules.az_net_008 as az_net_008
import scanner.rules.az_net_009 as az_net_009
import scanner.rules.az_net_010 as az_net_010
import scanner.rules.az_net_011 as az_net_011
import scanner.rules.az_net_012 as az_net_012
import scanner.rules.az_net_013 as az_net_013
import scanner.rules.az_net_014 as az_net_014
import scanner.rules.az_net_015 as az_net_015
import scanner.rules.az_net_016 as az_net_016
import scanner.rules.az_net_017 as az_net_017
from tests.helpers.mock_azure import make_resource

try:
    from azure.mgmt.network.models import SecurityRule, SecurityRuleAccess, SecurityRuleDirection

    _AZURE_SDK_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when SDK isn't installed
    _AZURE_SDK_AVAILABLE = False


def _install_network_client(monkeypatch, **collections):
    """Patch azure.mgmt.network.NetworkManagementClient with a fake exposing
    the given sub-resources, each as ``<attr>.list_all() -> list``."""

    def make_client(*args, **kwargs):
        ns = {}
        for attr, items in collections.items():
            ns[attr] = SimpleNamespace(list_all=lambda items=items: list(items))
        return SimpleNamespace(**ns)

    monkeypatch.setattr("azure.mgmt.network.NetworkManagementClient", make_client)


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
    "metadata",
}

_SUB = "00000000-0000-0000-0000-000000000001"
_RG = "rg-test"


def _nsg_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.Network/networkSecurityGroups/{name}"


def _allow_rule(name, port, source="10.0.0.0/24"):
    return make_resource(
        name=name,
        direction="Inbound",
        access="Allow",
        source_address_prefix=source,
        source_address_prefixes=[],
        destination_port_range=port,
        destination_port_ranges=[],
    )


def _open_allow_rule(name, port):
    return make_resource(
        name=name,
        direction="Inbound",
        access="Allow",
        source_address_prefix="0.0.0.0/0",
        source_address_prefixes=[],
        destination_port_range=port,
        destination_port_ranges=[],
    )


def test_net_001_compliant_returns_no_findings(mock_azure, subscription_id):
    """An NSG restricting SSH to a trusted IP range must produce no findings."""
    nsg = make_resource(
        id=_nsg_id("nsg-ssh-restricted"),
        name="nsg-ssh-restricted",
        security_rules=[_allow_rule("AllowSSHFromTrusted", "22", "10.0.0.0/24")],
    )
    mock_azure.set_network_security_groups([nsg])
    findings = az_net_001.scan(mock_azure, subscription_id)
    assert findings == []


def test_net_001_noncompliant_returns_one_finding(mock_azure, subscription_id):
    """An NSG with Allow-inbound-SSH-from-any must produce exactly one finding."""
    nsg = make_resource(
        id=_nsg_id("nsg-ssh-open"),
        name="nsg-ssh-open",
        security_rules=[_open_allow_rule("AllowSSHFromInternet", "22")],
    )
    mock_azure.set_network_security_groups([nsg])
    findings = az_net_001.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    finding = findings[0]
    assert _REQUIRED_FIELDS.issubset(finding.keys())
    assert finding["rule_id"] == "AZ-NET-001"
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "Network"
    assert finding["resource_name"] == "nsg-ssh-open"


def test_net_002_compliant_returns_no_findings(mock_azure, subscription_id):
    """An NSG restricting RDP to a trusted IP range must produce no findings."""
    nsg = make_resource(
        id=_nsg_id("nsg-rdp-restricted"),
        name="nsg-rdp-restricted",
        security_rules=[_allow_rule("AllowRDPFromTrusted", "3389", "192.168.1.0/24")],
    )
    mock_azure.set_network_security_groups([nsg])
    findings = az_net_002.scan(mock_azure, subscription_id)
    assert findings == []


def test_net_002_noncompliant_returns_one_finding(mock_azure, subscription_id):
    """An NSG with Allow-inbound-RDP-from-any must produce exactly one finding."""
    nsg = make_resource(
        id=_nsg_id("nsg-rdp-open"),
        name="nsg-rdp-open",
        security_rules=[_open_allow_rule("AllowRDPFromInternet", "3389")],
    )
    mock_azure.set_network_security_groups([nsg])
    findings = az_net_002.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    finding = findings[0]
    assert _REQUIRED_FIELDS.issubset(finding.keys())
    assert finding["rule_id"] == "AZ-NET-002"
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "Network"
    assert finding["resource_name"] == "nsg-rdp-open"


def _vnet_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.Network/virtualNetworks/{name}"


def _net_003_rule(name, direction="Inbound", access="Allow", source="0.0.0.0/0", source_list=None, port="443"):
    return make_resource(
        name=name,
        direction=direction,
        access=access,
        source_address_prefix=source,
        source_address_prefixes=source_list or [],
        destination_port_range=port,
    )


# ── AZ-NET-003: unrestricted inbound on 443 ─────────────────────────────────


def test_net_003_compliant_returns_no_findings(mock_azure, subscription_id):
    nsg = make_resource(
        id=_nsg_id("nsg-443-ok"),
        name="nsg-443-ok",
        security_rules=[_allow_rule("Allow443", "443", "10.0.0.0/24")],
    )
    mock_azure.set_network_security_groups([nsg])
    assert az_net_003.scan(mock_azure, subscription_id) == []


def test_net_003_noncompliant_returns_one_finding(mock_azure, subscription_id):
    nsg = make_resource(
        id=_nsg_id("nsg-443-open"),
        name="nsg-443-open",
        security_rules=[_open_allow_rule("Allow443Internet", "443")],
    )
    mock_azure.set_network_security_groups([nsg])
    findings = az_net_003.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-NET-003"
    assert findings[0]["severity"] == "HIGH"


def test_net_003_direction_is_case_insensitive(mock_azure, subscription_id):
    """COR-001: lowercase/mixed-case direction values must still be detected."""
    nsg = make_resource(
        id=_nsg_id("nsg-lowercase-direction"),
        name="nsg-lowercase-direction",
        security_rules=[_net_003_rule("AllowHTTPSLower", direction="inbound")],
    )
    mock_azure.set_network_security_groups([nsg])
    findings = az_net_003.scan(mock_azure, subscription_id)
    assert len(findings) == 1


def test_net_003_detects_plural_source_prefixes(mock_azure, subscription_id):
    """COR-002: an open source listed only in source_address_prefixes must be detected."""
    nsg = make_resource(
        id=_nsg_id("nsg-plural-prefix"),
        name="nsg-plural-prefix",
        security_rules=[
            _net_003_rule(
                "AllowHTTPSPluralOpen",
                source="",
                source_list=["0.0.0.0/0"],
            )
        ],
    )
    mock_azure.set_network_security_groups([nsg])
    findings = az_net_003.scan(mock_azure, subscription_id)
    assert len(findings) == 1


@pytest.mark.skipif(not _AZURE_SDK_AVAILABLE, reason="azure-mgmt-network not installed")
def test_net_003_detects_finding_with_real_sdk_enum_direction_and_access(mock_azure, subscription_id):
    """COR-001 (SDK model): real SecurityRuleDirection/Access enums, not plain strings,
    must still be detected. str(enum) yields e.g. "SecurityRuleDirection.INBOUND" rather
    than "Inbound", so the rule must normalise via .value instead of naive str()."""
    rule = SecurityRule(
        name="AllowHTTPSFromInternetEnum",
        direction=SecurityRuleDirection.INBOUND,
        access=SecurityRuleAccess.ALLOW,
        source_address_prefix="0.0.0.0/0",
        source_address_prefixes=[],
        destination_port_range="443",
    )
    nsg = make_resource(
        id=_nsg_id("nsg-443-open-enum"),
        name="nsg-443-open-enum",
        security_rules=[rule],
    )
    mock_azure.set_network_security_groups([nsg])
    findings = az_net_003.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-NET-003"


@pytest.mark.skipif(not _AZURE_SDK_AVAILABLE, reason="azure-mgmt-network not installed")
def test_net_003_compliant_with_real_sdk_enum_returns_no_findings(mock_azure, subscription_id):
    """COR-001 (SDK model): real SDK enums on a restricted rule must produce no findings."""
    rule = SecurityRule(
        name="AllowHTTPSFromTrustedEnum",
        direction=SecurityRuleDirection.INBOUND,
        access=SecurityRuleAccess.ALLOW,
        source_address_prefix="10.0.0.0/24",
        source_address_prefixes=[],
        destination_port_range="443",
    )
    nsg = make_resource(
        id=_nsg_id("nsg-443-restricted-enum"),
        name="nsg-443-restricted-enum",
        security_rules=[rule],
    )
    mock_azure.set_network_security_groups([nsg])
    findings = az_net_003.scan(mock_azure, subscription_id)
    assert findings == []


@pytest.mark.skipif(not _AZURE_SDK_AVAILABLE, reason="azure-mgmt-network not installed")
def test_net_003_detects_plural_source_prefixes_with_real_sdk_model(mock_azure, subscription_id):
    """COR-002 (SDK model): an open source only in source_address_prefixes, using a real
    SecurityRule instance with SDK enum fields, must still be detected and reported in
    finding metadata."""
    rule = SecurityRule(
        name="AllowHTTPSPluralOpenEnum",
        direction=SecurityRuleDirection.INBOUND,
        access=SecurityRuleAccess.ALLOW,
        source_address_prefix=None,
        source_address_prefixes=["0.0.0.0/0"],
        destination_port_range="443",
    )
    nsg = make_resource(
        id=_nsg_id("nsg-plural-prefix-enum"),
        name="nsg-plural-prefix-enum",
        security_rules=[rule],
    )
    mock_azure.set_network_security_groups([nsg])
    findings = az_net_003.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["matched_source_address_prefix"] == "0.0.0.0/0"


# ── AZ-NET-004: NSG with no rules ───────────────────────────────────────────


def test_net_004_compliant_returns_no_findings(mock_azure, subscription_id):
    nsg = make_resource(
        id=_nsg_id("nsg-has-rules"),
        name="nsg-has-rules",
        security_rules=[_allow_rule("AllowHTTPS", "443")],
    )
    mock_azure.set_network_security_groups([nsg])
    assert az_net_004.scan(mock_azure, subscription_id) == []


def test_net_004_noncompliant_returns_one_finding(mock_azure, subscription_id):
    nsg = make_resource(id=_nsg_id("nsg-empty"), name="nsg-empty", security_rules=[])
    mock_azure.set_network_security_groups([nsg])
    findings = az_net_004.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-NET-004"
    assert findings[0]["severity"] == "MEDIUM"


# ── AZ-NET-005: VNet without DDoS protection ────────────────────────────────


def test_net_005_compliant_returns_no_findings(mock_azure, subscription_id):
    vnet = make_resource(
        id=_vnet_id("vnet-ddos"),
        name="vnet-ddos",
        ddos_protection_plan=make_resource(id="plan1"),
        enable_ddos_protection=True,
    )
    mock_azure.set_virtual_networks([vnet])
    assert az_net_005.scan(mock_azure, subscription_id) == []


def test_net_005_noncompliant_returns_one_finding(mock_azure, subscription_id):
    vnet = make_resource(
        id=_vnet_id("vnet-noddos"),
        name="vnet-noddos",
        ddos_protection_plan=None,
        enable_ddos_protection=False,
    )
    mock_azure.set_virtual_networks([vnet])
    findings = az_net_005.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-NET-005"
    assert findings[0]["severity"] == "LOW"


# ── AZ-NET-006: unassociated public IP ──────────────────────────────────────


def test_net_006_compliant_returns_no_findings(mock_azure, subscription_id):
    pip = make_resource(
        id="/pip/associated",
        name="pip-associated",
        ip_configuration=make_resource(id="nic-ipcfg"),
        nat_gateway=None,
    )
    mock_azure.set_public_ip_addresses([pip])
    assert az_net_006.scan(mock_azure, subscription_id) == []


def test_net_006_noncompliant_returns_one_finding(mock_azure, subscription_id):
    pip = make_resource(
        id="/pip/orphan",
        name="pip-orphan",
        ip_configuration=None,
        nat_gateway=None,
        ip_address="20.1.2.3",
        sku=make_resource(name="Standard"),
    )
    mock_azure.set_public_ip_addresses([pip])
    findings = az_net_006.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-NET-006"
    assert findings[0]["severity"] == "LOW"


# ── AZ-NET-007: Application Gateway without WAF (SDK) ────────────────────────


def test_net_007_compliant_returns_no_findings(mock_azure, subscription_id, monkeypatch):
    agw = make_resource(
        id="/agw1",
        name="agw-waf",
        location="eastus",
        sku=make_resource(name="WAF_v2"),
        web_application_firewall_configuration=make_resource(enabled=True),
    )
    _install_network_client(monkeypatch, application_gateways=[agw])
    assert az_net_007.scan(mock_azure, subscription_id) == []


def test_net_007_noncompliant_returns_one_finding(mock_azure, subscription_id, monkeypatch):
    agw = make_resource(
        id="/agw2",
        name="agw-nowaf",
        location="eastus",
        sku=make_resource(name="Standard_v2"),
        web_application_firewall_configuration=None,
    )
    _install_network_client(monkeypatch, application_gateways=[agw])
    findings = az_net_007.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-NET-007"
    assert findings[0]["severity"] == "HIGH"


# ── AZ-NET-008: Load balancer with no backend pool (accessor) ───────────────


def test_net_008_compliant_returns_no_findings(mock_azure, subscription_id):
    lb = make_resource(
        id="/lb1",
        name="lb-ok",
        location="eastus",
        backend_address_pools=[make_resource(name="pool1")],
    )
    mock_azure.set_load_balancers([lb])
    assert az_net_008.scan(mock_azure, subscription_id) == []


def test_net_008_noncompliant_returns_one_finding(mock_azure, subscription_id):
    lb = make_resource(id="/lb2", name="lb-empty", location="eastus", backend_address_pools=[])
    mock_azure.set_load_balancers([lb])
    findings = az_net_008.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-NET-008"
    assert findings[0]["severity"] == "LOW"


# ── AZ-NET-009: VPN gateway using IKEv1 (SDK) ───────────────────────────────
# NOTE / BUG: the rule calls
#   client.virtual_network_gateway_connections.list_all()
# but the real azure-mgmt-network SDK exposes only .list(resource_group) on that
# operations group — there is NO list_all(). In production the AttributeError is
# swallowed by the rule's except, so AZ-NET-009 NEVER fires (silent false
# negative). The fake client below provides list_all() so these tests can still
# validate the rule's intended IKEv1 detection logic — see the validation report.


def test_net_009_compliant_returns_no_findings(mock_azure, subscription_id, monkeypatch):
    conn = make_resource(
        id="/conn1",
        name="conn-ikev2",
        location="eastus",
        connection_protocol="IKEv2",
        connection_type="IPsec",
    )
    _install_network_client(monkeypatch, virtual_network_gateway_connections=[conn])
    assert az_net_009.scan(mock_azure, subscription_id) == []


def test_net_009_noncompliant_returns_one_finding(mock_azure, subscription_id, monkeypatch):
    conn = make_resource(
        id="/conn2",
        name="conn-ikev1",
        location="eastus",
        connection_protocol="IKEv1",
        connection_type="IPsec",
    )
    _install_network_client(monkeypatch, virtual_network_gateway_connections=[conn])
    findings = az_net_009.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-NET-009"
    assert findings[0]["severity"] == "HIGH"


# ── AZ-NET-010: subnet with no NSG (SDK) ────────────────────────────────────


def test_net_010_compliant_returns_no_findings(mock_azure, subscription_id, monkeypatch):
    vnet = make_resource(
        id=_vnet_id("vnet-subnets"),
        name="vnet-subnets",
        subnets=[
            make_resource(
                name="app-subnet",
                id="/subnet/app",
                network_security_group=make_resource(id="nsg1"),
                address_prefix="10.0.1.0/24",
            )
        ],
    )
    _install_network_client(monkeypatch, virtual_networks=[vnet])
    assert az_net_010.scan(mock_azure, subscription_id) == []


def test_net_010_noncompliant_returns_one_finding(mock_azure, subscription_id, monkeypatch):
    vnet = make_resource(
        id=_vnet_id("vnet-bare"),
        name="vnet-bare",
        subnets=[
            make_resource(
                name="bare-subnet",
                id="/subnet/bare",
                network_security_group=None,
                address_prefix="10.0.2.0/24",
            )
        ],
    )
    _install_network_client(monkeypatch, virtual_networks=[vnet])
    findings = az_net_010.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-NET-010"
    assert findings[0]["severity"] == "HIGH"


def test_net_010_skips_reserved_subnets(mock_azure, subscription_id, monkeypatch):
    """Gateway/Firewall/Bastion subnets without an NSG must not be flagged."""
    vnet = make_resource(
        id=_vnet_id("vnet-gw"),
        name="vnet-gw",
        subnets=[
            make_resource(
                name="GatewaySubnet",
                id="/subnet/gw",
                network_security_group=None,
                address_prefix="10.0.3.0/24",
            )
        ],
    )
    _install_network_client(monkeypatch, virtual_networks=[vnet])
    assert az_net_010.scan(mock_azure, subscription_id) == []


# ── AZ-NET-011: Network Watcher not enabled in all regions ──────────────────


def test_net_011_compliant_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_regions_with_resources(["eastus", "westus"])
    mock_azure.set_network_watcher_regions(["eastus", "westus"])
    assert az_net_011.scan(mock_azure, subscription_id) == []


def test_net_011_noncompliant_returns_finding_per_unmonitored_region(mock_azure, subscription_id):
    mock_azure.set_regions_with_resources(["eastus", "westus"])
    mock_azure.set_network_watcher_regions(["eastus"])
    findings = az_net_011.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-NET-011"
    assert findings[0]["severity"] == "LOW"
    assert findings[0]["resource_name"] == "westus"


# ── AZ-NET-012: VNet flow logs not enabled ──────────────────────────────────
# The real AzureClient.get_flow_logs() lists Network Watcher flow logs
# per-region (a subscription has no flat "all flow logs" endpoint), returning
# a dict keyed by normalized region: a list of FlowLog resources for a region
# with a reachable watcher, or None for a region whose watcher/flow-log
# listing failed (403/429/etc). A region never set at all behaves the same as
# None — both must be treated as indeterminate, never as "no flow log exists".


def _net_012_vnet(name="vnet-1", location="eastus", nsg_id=None):
    subnet = make_resource(
        name="default",
        network_security_group=make_resource(id=nsg_id) if nsg_id else None,
    )
    return make_resource(id=_vnet_id(name), name=name, location=location, subnets=[subnet])


def test_net_012_no_vnets_returns_no_findings(mock_azure, subscription_id):
    assert az_net_012.scan(mock_azure, subscription_id) == []


def test_net_012_compliant_vnet_flow_log_returns_no_findings(mock_azure, subscription_id):
    vnet = _net_012_vnet()
    mock_azure.set_virtual_networks([vnet])
    mock_azure.set_flow_logs_by_region("eastus", [make_resource(target_resource_id=vnet.id, enabled=True)])
    assert az_net_012.scan(mock_azure, subscription_id) == []


def test_net_012_noncompliant_returns_one_finding(mock_azure, subscription_id):
    vnet = _net_012_vnet()
    mock_azure.set_virtual_networks([vnet])
    mock_azure.set_flow_logs_by_region("eastus", [])  # watcher reachable, no flow log configured
    findings = az_net_012.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    finding = findings[0]
    assert _REQUIRED_FIELDS.issubset(finding.keys())
    assert finding["rule_id"] == "AZ-NET-012"
    assert finding["severity"] == "MEDIUM"
    assert finding["resource_type"] == "Microsoft.Network/virtualNetworks"
    assert finding["resource_name"] == "vnet-1"
    assert finding["remediation"].startswith("Enable a VNet flow log")  # never instructs creating a new NSG flow log


def test_net_012_disabled_vnet_flow_log_still_flags(mock_azure, subscription_id):
    """A present-but-disabled flow log is not coverage — must still flag."""
    vnet = _net_012_vnet()
    mock_azure.set_virtual_networks([vnet])
    mock_azure.set_flow_logs_by_region("eastus", [make_resource(target_resource_id=vnet.id, enabled=False)])
    assert len(az_net_012.scan(mock_azure, subscription_id)) == 1


def test_net_012_existing_legacy_nsg_flow_log_is_accepted_not_flagged(mock_azure, subscription_id):
    """An existing (not newly created) NSG flow log on the VNet's own subnet
    NSG must be accepted as coverage — new NSG flow log creation is blocked
    by Microsoft, so this rule must never recommend creating one."""
    nsg_id = _nsg_id("nsg-legacy")
    vnet = _net_012_vnet(nsg_id=nsg_id)
    mock_azure.set_virtual_networks([vnet])
    mock_azure.set_flow_logs_by_region("eastus", [make_resource(target_resource_id=nsg_id, enabled=True)])
    assert az_net_012.scan(mock_azure, subscription_id) == []


def test_net_012_disabled_legacy_nsg_flow_log_still_flags(mock_azure, subscription_id):
    nsg_id = _nsg_id("nsg-legacy-disabled")
    vnet = _net_012_vnet(nsg_id=nsg_id)
    mock_azure.set_virtual_networks([vnet])
    mock_azure.set_flow_logs_by_region("eastus", [make_resource(target_resource_id=nsg_id, enabled=False)])
    assert len(az_net_012.scan(mock_azure, subscription_id)) == 1


def test_net_012_region_never_set_is_indeterminate_not_flagged(mock_azure, subscription_id):
    """No Network Watcher found for this region at all — must not flag."""
    mock_azure.set_virtual_networks([_net_012_vnet(location="westus")])
    # No set_flow_logs_by_region("westus", ...) call at all.
    assert az_net_012.scan(mock_azure, subscription_id) == []


def test_net_012_region_collection_failure_is_indeterminate_not_flagged(mock_azure, subscription_id):
    """403/429/other API failure listing a region's flow logs (modeled as
    None) must never be scored as a confirmed missing flow log."""
    mock_azure.set_virtual_networks([_net_012_vnet(location="eastus")])
    mock_azure.set_flow_logs_by_region("eastus", None)
    assert az_net_012.scan(mock_azure, subscription_id) == []


def test_net_012_partial_collection_only_skips_the_failed_region(mock_azure, subscription_id):
    """One region's flow-log evidence failing must not suppress a genuine
    finding in a region that was collected successfully."""
    ok_vnet = _net_012_vnet(name="vnet-ok-region", location="eastus")
    failed_vnet = _net_012_vnet(name="vnet-failed-region", location="westus")
    mock_azure.set_virtual_networks([ok_vnet, failed_vnet])
    mock_azure.set_flow_logs_by_region("eastus", [])  # reachable, genuinely no flow log
    mock_azure.set_flow_logs_by_region("westus", None)  # collection failed
    findings = az_net_012.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["resource_name"] == "vnet-ok-region"


# ── AZ-NET-013: Azure Firewall not enabled on VNet ──────────────────────────


def test_net_013_compliant_returns_no_findings(mock_azure, subscription_id):
    vnet_id = _vnet_id("vnet-fw")
    fw = make_resource(
        ip_configurations=[make_resource(subnet=make_resource(id=f"{vnet_id}/subnets/AzureFirewallSubnet"))]
    )
    mock_azure.set_all_azure_firewalls([fw])
    mock_azure.set_virtual_networks([make_resource(id=vnet_id, name="vnet-fw", location="eastus")])
    assert az_net_013.scan(mock_azure, subscription_id) == []


def test_net_013_noncompliant_returns_one_finding(mock_azure, subscription_id):
    vnet_id = _vnet_id("vnet-unprotected")
    mock_azure.set_all_azure_firewalls([])  # empty list, not None
    mock_azure.set_virtual_networks([make_resource(id=vnet_id, name="vnet-unprotected", location="eastus")])
    findings = az_net_013.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-NET-013"
    assert findings[0]["severity"] == "HIGH"


def test_net_013_firewall_listing_none_skips(mock_azure, subscription_id):
    """When the firewall listing fails (None) the rule must not flag VNets."""
    mock_azure.set_all_azure_firewalls(None)
    mock_azure.set_virtual_networks([make_resource(id=_vnet_id("v"), name="v", location="eastus")])
    assert az_net_013.scan(mock_azure, subscription_id) == []


# ── AZ-NET-014: VNet peering without gateway-transit restrictions ───────────


def test_net_014_compliant_returns_no_findings(mock_azure, subscription_id):
    vnet = make_resource(id=_vnet_id("vnet-peer-ok"), name="vnet-peer-ok")
    mock_azure.set_virtual_networks([vnet])
    mock_azure.set_vnet_peerings(
        _RG, "vnet-peer-ok", [make_resource(name="peer1", allow_gateway_transit=False, use_remote_gateways=False)]
    )
    assert az_net_014.scan(mock_azure, subscription_id) == []


def test_net_014_noncompliant_returns_one_finding(mock_azure, subscription_id):
    vnet = make_resource(id=_vnet_id("vnet-peer-bad"), name="vnet-peer-bad")
    mock_azure.set_virtual_networks([vnet])
    mock_azure.set_vnet_peerings(
        _RG, "vnet-peer-bad", [make_resource(name="peer1", allow_gateway_transit=True, use_remote_gateways=False)]
    )
    findings = az_net_014.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-NET-014"
    assert findings[0]["severity"] == "MEDIUM"


# ── AZ-NET-015: public DNS zone exposing internal infrastructure ────────────


def _dns_zone_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.Network/dnsZones/{name}"


def test_net_015_compliant_public_records_returns_no_findings(mock_azure, subscription_id):
    """A public zone with only public IPs and non-internal names is compliant."""
    zone = make_resource(id=_dns_zone_id("example.com"), name="example.com", zone_type="Public")
    mock_azure.set_dns_zones([zone])
    mock_azure.set_dns_record_sets(
        _RG,
        "example.com",
        [
            make_resource(name="www", a_records=[make_resource(ipv4_address="20.1.2.3")]),
        ],
    )
    assert az_net_015.scan(mock_azure, subscription_id) == []


def test_net_015_noncompliant_rfc1918_record_returns_one_finding(mock_azure, subscription_id):
    """A public zone with an A record pointing at an RFC1918 IP must flag."""
    zone = make_resource(id=_dns_zone_id("corp.example.com"), name="corp.example.com", zone_type="Public")
    mock_azure.set_dns_zones([zone])
    mock_azure.set_dns_record_sets(
        _RG,
        "corp.example.com",
        [
            make_resource(name="app", a_records=[make_resource(ipv4_address="10.0.0.5")]),
        ],
    )
    findings = az_net_015.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-NET-015"
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["resource_name"] == "corp.example.com"


def test_net_015_skips_private_zone(mock_azure, subscription_id):
    """A non-public (Private) zone must never be flagged, even with RFC1918 records."""
    zone = make_resource(id=_dns_zone_id("internal.local"), name="internal.local", zone_type="Private")
    mock_azure.set_dns_zones([zone])
    mock_azure.set_dns_record_sets(
        _RG,
        "internal.local",
        [
            make_resource(name="db", a_records=[make_resource(ipv4_address="10.0.0.9")]),
        ],
    )
    assert az_net_015.scan(mock_azure, subscription_id) == []


# ── AZ-NET-016: NIC IP forwarding ──────────────────────────────────────────


def test_net_016_empty_and_failed_inventory_create_no_findings(mock_azure, subscription_id):
    mock_azure.set_network_interfaces([])
    assert az_net_016.scan(mock_azure, subscription_id) == []
    mock_azure.set_network_interfaces(None)
    assert az_net_016.scan(mock_azure, subscription_id) == []


def test_net_016_disabled_ip_forwarding_is_compliant(mock_azure, subscription_id):
    mock_azure.set_network_interfaces(
        [
            make_resource(
                id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic1",
                name="nic1",
                enable_ip_forwarding=False,
            )
        ]
    )
    assert az_net_016.scan(mock_azure, subscription_id) == []


def test_net_016_enabled_ip_forwarding_creates_finding(mock_azure, subscription_id):
    nic_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic1"
    mock_azure.set_network_interfaces([make_resource(id=nic_id, name="nic1", enable_ip_forwarding=True)])
    findings = az_net_016.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-NET-016"
    assert findings[0]["metadata"]["requires_routing_function_review"] is True


# ── AZ-NET-017: direct Internet default UDR ─────────────────────────────────


def test_net_017_empty_and_failed_inventory_create_no_findings(mock_azure, subscription_id):
    mock_azure.set_route_tables([])
    assert az_net_017.scan(mock_azure, subscription_id) == []
    mock_azure.set_route_tables(None)
    assert az_net_017.scan(mock_azure, subscription_id) == []


def test_net_017_private_route_and_inspected_default_are_compliant(mock_azure, subscription_id):
    routes = [
        make_resource(name="private", address_prefix="10.0.0.0/8", next_hop_type="Internet"),
        make_resource(name="default", address_prefix="0.0.0.0/0", next_hop_type="VirtualAppliance"),
    ]
    mock_azure.set_route_tables([make_resource(id="/routeTables/rt1", name="rt1", routes=routes)])
    assert az_net_017.scan(mock_azure, subscription_id) == []


@pytest.mark.parametrize("prefix", ["0.0.0.0/0", "::/0"])
def test_net_017_direct_internet_default_creates_finding(mock_azure, subscription_id, prefix):
    route = make_resource(
        id="/routeTables/rt1/routes/default",
        name="default",
        address_prefix=prefix,
        next_hop_type="Internet",
    )
    mock_azure.set_route_tables([make_resource(id="/routeTables/rt1", name="rt1", routes=[route])])
    findings = az_net_017.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-NET-017"
    assert findings[0]["metadata"]["address_prefix"] == prefix
