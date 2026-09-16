"""Completeness and API regression tests for Network Layer assurance."""

import copy
from datetime import date
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from api.services.assurance_catalog import CatalogValidationError
from api.services.network_layer_assurance import (
    EXPECTED_CONTROL_IDS,
    EXPECTED_DOMAIN_IDS,
    EXPECTED_RULE_IDS,
    EXPECTED_SUBDOMAIN_IDS,
    build_report,
    load_catalog,
    validate_catalog,
)


def test_catalog_covers_all_domains_and_audits_all_network_rules():
    catalog = load_catalog()
    assert {item["id"] for item in catalog["domains"]} == EXPECTED_DOMAIN_IDS
    assert {item["id"] for item in catalog["subdomains"]} == EXPECTED_SUBDOMAIN_IDS
    assert {item["id"] for item in catalog["controls"]} == EXPECTED_CONTROL_IDS
    assert {item["id"] for item in catalog["rule_classifications"]} == EXPECTED_RULE_IDS
    assert all(domain["responsibility_owner"] for domain in catalog["domains"])
    assert all(domain["azure_applicability"] for domain in catalog["domains"])
    assert all(domain["observability_method"] for domain in catalog["domains"])
    assert all(domain["evidence_source_ids"] for domain in catalog["domains"])
    assert all(domain["automation_decision"] for domain in catalog["domains"])


def test_rule_audit_matches_every_network_rule_file():
    rules_dir = Path(__file__).resolve().parents[1] / "scanner" / "rules"
    discovered_ids = {f"AZ-NET-{path.stem.rsplit('_', 1)[1]}" for path in rules_dir.glob("az_net_[0-9][0-9][0-9].py")}
    classified_ids = {item["id"] for item in load_catalog()["rule_classifications"] if item["id"].startswith("AZ-NET-")}
    assert classified_ids == discovered_ids


def test_controls_cover_every_domain_and_subdomain():
    catalog = load_catalog()
    covered_domains = {domain_id for control in catalog["controls"] for domain_id in control["domain_ids"]}
    covered_subdomains = {subdomain_id for control in catalog["controls"] for subdomain_id in control["subdomain_ids"]}
    assert covered_domains == EXPECTED_DOMAIN_IDS
    assert covered_subdomains == EXPECTED_SUBDOMAIN_IDS
    assert all(control["evidence_source_ids"] for control in catalog["controls"])
    assert all("scanner_rule_ids" in control for control in catalog["controls"])


@pytest.mark.parametrize(
    ("mutation", "error_match"),
    [
        (lambda catalog: catalog["domains"].pop(), "complete NL-01 through NL-20"),
        (lambda catalog: catalog["subdomains"].pop(), "complete Layer 3 functional set"),
        (lambda catalog: catalog["controls"].pop(), "complete NL-C01 through NL-C20"),
        (lambda catalog: catalog["rule_classifications"].pop(), "both MACsec rules"),
        (lambda catalog: catalog["domains"][0].pop("responsibility_owner"), "responsibility_owner"),
        (lambda catalog: catalog["domains"][0].pop("azure_applicability"), "azure_applicability"),
        (lambda catalog: catalog["domains"][0].pop("evidence_source_ids"), "evidence_source_ids"),
        (lambda catalog: catalog["domains"][0].pop("automation_decision"), "automation_decision"),
        (lambda catalog: catalog["rule_classifications"][2].pop("classification_basis"), "classification_basis"),
    ],
)
def test_catalog_fails_closed_on_missing_required_content(mutation, error_match):
    catalog = copy.deepcopy(load_catalog())
    mutation(catalog)
    with pytest.raises(CatalogValidationError, match=error_match):
        validate_catalog(catalog)


def test_port_dns_and_macsec_rules_are_not_relabelled_as_layer_3():
    rules = {item["id"]: item for item in load_catalog()["rule_classifications"]}
    port_rules = ("AZ-NET-001", "AZ-NET-002", "AZ-NET-003")
    assert {rules[rule_id]["osi_classification"] for rule_id in port_rules} == {"Layer 4"}
    assert rules["AZ-NET-015"]["osi_classification"] == "Layer 7"
    assert rules["AZ-DL-001"]["osi_classification"] == "Layer 2"
    assert rules["AZ-DL-002"]["osi_classification"] == "Layer 2"
    excluded_rules = (*port_rules, "AZ-NET-015", "AZ-DL-001", "AZ-DL-002")
    assert all(not rules[rule_id]["layer_3_domain_ids"] for rule_id in excluded_rules)


def test_report_separates_catalog_coverage_from_evidence_freshness():
    report = build_report(load_catalog(), as_of=date(2028, 1, 1))
    assert report["catalog_coverage"] == {
        "controls_covered": 20,
        "controls_total": 20,
        "domains_covered": 20,
        "domains_total": 20,
        "subdomains_covered": 5,
        "subdomains_total": 5,
        "percent": 100,
    }
    assert report["evidence_freshness"]["percent"] == 0
    assert report["provider_assurance_state"] == "DOCUMENTED"
    assert report["platform_enforcement_state"] == "DOCUMENTED_NOT_LIVE_INSPECTED"
    assert report["automated_control_applicability"]["empty_inventory"] == "NOT_APPLICABLE"
    assert report["automated_control_applicability"]["api_or_permission_failure"] == "INDETERMINATE"


def test_network_layer_endpoint_requires_authentication(client):
    assert client.get("/api/assurance/network-layer").status_code == 401


def test_network_layer_endpoint_returns_complete_report(client, auth_headers):
    response = client.get("/api/assurance/network-layer", headers=auth_headers)
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["layer"] == {
        "number": 3,
        "name": "Network",
        "model": "OSI",
        "assessment_type": "mixed_assurance",
    }
    assert payload["catalog_coverage"]["percent"] == 100
    assert len(payload["domains"]) == 20
    assert len(payload["subdomains"]) == 5
    assert len(payload["controls"]) == 20
    assert len(payload["rule_classifications"]) == 29


def test_network_layer_endpoint_hides_catalog_errors(client, auth_headers):
    with patch(
        "api.routes.assurance.get_network_layer_assurance_report",
        side_effect=CatalogValidationError("sensitive path"),
    ):
        response = client.get("/api/assurance/network-layer", headers=auth_headers)
    assert response.status_code == 500
    assert response.get_json() == {"error": "Network Layer assurance catalog is unavailable"}
    assert "sensitive path" not in response.get_data(as_text=True)


def test_layer_3_inventory_uses_azure_client_abstraction():
    from scanner.azure_client import AzureClient

    sdk_client = MagicMock()
    sdk_client.network_interfaces.list_all.return_value = [SimpleNamespace(name="nic1")]
    sdk_client.route_tables.list_all.return_value = [SimpleNamespace(name="rt1")]
    with patch("scanner.azure_client.NetworkManagementClient", return_value=sdk_client):
        azure_client = AzureClient("sub-1", credential=MagicMock())
        assert [nic.name for nic in azure_client.get_network_interfaces()] == ["nic1"]
        assert [table.name for table in azure_client.get_route_tables()] == ["rt1"]


def test_layer_3_inventory_preserves_api_failure():
    from scanner.azure_client import AzureClient

    with patch("scanner.azure_client.NetworkManagementClient", side_effect=PermissionError("denied")):
        azure_client = AzureClient("sub-1", credential=MagicMock())
        assert azure_client.get_network_interfaces() is None
        assert azure_client.get_route_tables() is None
