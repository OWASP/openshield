"""Load, validate, and report Azure Network Layer assurance coverage."""

from __future__ import annotations

import copy
import json
from datetime import date
from pathlib import Path
from typing import Any

from api.services.assurance_catalog import (
    CatalogValidationError,
    require_reference_list,
    require_string,
    require_unique,
    validate_evidence_source,
)

CATALOG_PATH = Path(__file__).resolve().parents[2] / "compliance" / "assurance" / "network_layer.json"
EXPECTED_DOMAIN_IDS = {f"NL-{number:02d}" for number in range(1, 21)}
EXPECTED_SUBDOMAIN_IDS = {"ADDRESSING", "ROUTING", "TRANSIT", "PROTECTION", "OBSERVABILITY"}
EXPECTED_CONTROL_IDS = {f"NL-C{number:02d}" for number in range(1, 21)}
EXPECTED_RULE_IDS = {f"AZ-NET-{number:03d}" for number in range(1, 28)} | {"AZ-DL-001", "AZ-DL-002"}
ALLOWED_RESPONSIBILITIES = {"Microsoft", "Customer", "Shared"}
ALLOWED_APPLICABILITY = {"APPLICABLE", "NOT_APPLICABLE", "UNSUPPORTED"}
ALLOWED_VERIFICATION = {
    "PROVIDER_ATTESTED",
    "PLATFORM_ENFORCED",
    "AUTOMATICALLY_CHECKED",
    "MANUALLY_VERIFIABLE",
    "UNSUPPORTED",
    "NOT_APPLICABLE",
}
ALLOWED_CLASSIFICATIONS = {"Layer 2", "Layer 3", "Layer 4", "Layer 7", "Cross-layer"}
ALLOWED_CONTROL_STATUSES = {"DOCUMENTED", "REVIEW_DUE"}


def validate_catalog(catalog: dict[str, Any]) -> None:
    """Fail closed when any Layer 3 domain, rule audit, decision, or reference is missing."""
    if not isinstance(catalog, dict):
        raise CatalogValidationError("Catalog root must be an object")
    layer = catalog.get("layer")
    if not isinstance(layer, dict) or layer.get("number") != 3 or layer.get("name") != "Network":
        raise CatalogValidationError("Catalog must describe OSI Layer 3 Network")
    require_string(catalog, "catalog_version", "catalog")
    if catalog.get("schema_version") != 1:
        raise CatalogValidationError("schema_version must be 1")
    scope = catalog.get("scope")
    if not isinstance(scope, dict):
        raise CatalogValidationError("scope must be an object")
    require_string(scope, "statement", "scope")
    require_string(scope, "responsibility_boundary", "scope")
    if scope.get("environment") != "azure_public_cloud":
        raise CatalogValidationError("scope.environment must be azure_public_cloud")

    domains = require_unique(catalog.get("domains"), "domains")
    subdomains = require_unique(catalog.get("subdomains"), "subdomains")
    controls = require_unique(catalog.get("controls"), "controls")
    evidence = require_unique(catalog.get("evidence_sources"), "evidence_sources")
    rules = require_unique(catalog.get("rule_classifications"), "rule_classifications")
    if set(domains) != EXPECTED_DOMAIN_IDS:
        raise CatalogValidationError("domains must contain the complete NL-01 through NL-20 set")
    if set(subdomains) != EXPECTED_SUBDOMAIN_IDS:
        raise CatalogValidationError("subdomains must contain the complete Layer 3 functional set")
    if set(controls) != EXPECTED_CONTROL_IDS:
        raise CatalogValidationError("controls must contain the complete NL-C01 through NL-C20 set")
    if set(rules) != EXPECTED_RULE_IDS:
        raise CatalogValidationError(
            "rule_classifications must contain AZ-NET-001 through AZ-NET-027 and both MACsec rules"
        )

    for evidence_id, source in evidence.items():
        validate_evidence_source(source, evidence_id, {"learn.microsoft.com"})
    for subdomain_id, subdomain in subdomains.items():
        require_string(subdomain, "name", subdomain_id)
        require_string(subdomain, "description", subdomain_id)

    referenced_evidence: set[str] = set()
    referenced_rules: set[str] = set()
    covered_domains: set[str] = set()
    covered_subdomains: set[str] = set()
    for control_id, control in controls.items():
        require_string(control, "title", control_id)
        responsibility = require_string(control, "responsibility", control_id)
        applicability = require_string(control, "applicability", control_id)
        verification = require_string(control, "verification", control_id)
        status = require_string(control, "status", control_id)
        if responsibility not in ALLOWED_RESPONSIBILITIES:
            raise CatalogValidationError(f"{control_id}: invalid responsibility")
        if applicability not in ALLOWED_APPLICABILITY:
            raise CatalogValidationError(f"{control_id}: invalid applicability")
        if verification not in ALLOWED_VERIFICATION:
            raise CatalogValidationError(f"{control_id}: invalid verification")
        if status not in ALLOWED_CONTROL_STATUSES:
            raise CatalogValidationError(f"{control_id}: invalid status")
        covered_domains.update(require_reference_list(control, "domain_ids", set(domains), control_id))
        covered_subdomains.update(require_reference_list(control, "subdomain_ids", set(subdomains), control_id))
        referenced_evidence.update(require_reference_list(control, "evidence_source_ids", set(evidence), control_id))
        scanner_rule_ids = control.get("scanner_rule_ids")
        if not isinstance(scanner_rule_ids, list) or any(not isinstance(rule_id, str) for rule_id in scanner_rule_ids):
            raise CatalogValidationError(f"{control_id}: scanner_rule_ids must be a list of strings")
        if len(scanner_rule_ids) != len(set(scanner_rule_ids)) or set(scanner_rule_ids) - set(rules):
            raise CatalogValidationError(f"{control_id}: scanner_rule_ids contains invalid references")
        referenced_rules.update(scanner_rule_ids)

    if covered_domains != set(domains):
        raise CatalogValidationError(f"Uncovered Network Layer domains: {sorted(set(domains) - covered_domains)}")
    if covered_subdomains != set(subdomains):
        raise CatalogValidationError(
            f"Uncovered Network Layer subdomains: {sorted(set(subdomains) - covered_subdomains)}"
        )

    for domain_id, domain in domains.items():
        require_string(domain, "name", domain_id)
        require_string(domain, "observability_method", domain_id)
        require_string(domain, "automation_decision", domain_id)
        responsibility = require_string(domain, "responsibility_owner", domain_id)
        applicability = require_string(domain, "azure_applicability", domain_id)
        verification = require_string(domain, "verification", domain_id)
        if responsibility not in ALLOWED_RESPONSIBILITIES:
            raise CatalogValidationError(f"{domain_id}: invalid responsibility_owner")
        if applicability not in ALLOWED_APPLICABILITY:
            raise CatalogValidationError(f"{domain_id}: invalid azure_applicability")
        if verification not in ALLOWED_VERIFICATION:
            raise CatalogValidationError(f"{domain_id}: invalid verification")
        domain_evidence = require_reference_list(domain, "evidence_source_ids", set(evidence), domain_id)
        referenced_evidence.update(domain_evidence)
        rule_ids = domain.get("rule_ids")
        if not isinstance(rule_ids, list) or any(not isinstance(rule_id, str) for rule_id in rule_ids):
            raise CatalogValidationError(f"{domain_id}: rule_ids must be a list of strings")
        if len(rule_ids) != len(set(rule_ids)) or set(rule_ids) - set(rules):
            raise CatalogValidationError(f"{domain_id}: rule_ids contains invalid references")

    if referenced_evidence != set(evidence):
        raise CatalogValidationError("every evidence source must be referenced")

    for rule_id, rule in rules.items():
        require_string(rule, "name", rule_id)
        classification = require_string(rule, "osi_classification", rule_id)
        require_string(rule, "classification_basis", rule_id)
        if classification not in ALLOWED_CLASSIFICATIONS:
            raise CatalogValidationError(f"{rule_id}: invalid osi_classification")
        domain_ids = rule.get("layer_3_domain_ids")
        if not isinstance(domain_ids, list) or any(not isinstance(item, str) for item in domain_ids):
            raise CatalogValidationError(f"{rule_id}: layer_3_domain_ids must be a list of strings")
        if len(domain_ids) != len(set(domain_ids)) or set(domain_ids) - set(domains):
            raise CatalogValidationError(f"{rule_id}: invalid Layer 3 domain reference")
        if classification == "Layer 3" and not domain_ids:
            raise CatalogValidationError(f"{rule_id}: Layer 3 rules must cross-reference a domain")
        if classification not in {"Layer 3", "Cross-layer"} and domain_ids:
            raise CatalogValidationError(f"{rule_id}: non-Layer 3 rules cannot claim Layer 3 coverage")
        if domain_ids and rule_id not in referenced_rules:
            raise CatalogValidationError(f"{rule_id}: domain cross-reference is not reciprocal")


def load_catalog(path: Path = CATALOG_PATH) -> dict[str, Any]:
    """Load and validate the bundled catalog."""
    try:
        with path.open(encoding="utf-8") as catalog_file:
            catalog = json.load(catalog_file)
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogValidationError(f"Unable to load Network Layer assurance catalog: {exc}") from exc
    validate_catalog(catalog)
    return catalog


def build_report(catalog: dict[str, Any], as_of: date | None = None) -> dict[str, Any]:
    """Build static responsibility coverage with independent evidence freshness."""
    validate_catalog(catalog)
    report = copy.deepcopy(catalog)
    as_of = as_of or date.today()
    evidence = {item["id"]: item for item in report["evidence_sources"]}
    current = sum(date.fromisoformat(item["review_due_at"]) >= as_of for item in evidence.values())
    for domain in report["domains"]:
        domain["evidence"] = [evidence[source_id] for source_id in domain["evidence_source_ids"]]
        domain["control_ids"] = [
            control["id"] for control in report["controls"] if domain["id"] in control["domain_ids"]
        ]
        domain["subdomain_ids"] = sorted(
            {
                subdomain_id
                for control in report["controls"]
                if domain["id"] in control["domain_ids"]
                for subdomain_id in control["subdomain_ids"]
            }
        )
    for subdomain in report["subdomains"]:
        subdomain["control_ids"] = [
            control["id"] for control in report["controls"] if subdomain["id"] in control["subdomain_ids"]
        ]
        subdomain["domain_ids"] = sorted(
            {
                domain_id
                for control in report["controls"]
                if subdomain["id"] in control["subdomain_ids"]
                for domain_id in control["domain_ids"]
            }
        )
    report["catalog_coverage"] = {
        "controls_covered": 20,
        "controls_total": 20,
        "domains_covered": 20,
        "domains_total": 20,
        "subdomains_covered": 5,
        "subdomains_total": 5,
        "percent": 100,
    }
    report["evidence_freshness"] = {
        "current_sources": current,
        "total_sources": len(evidence),
        "percent": round(current / len(evidence) * 100) if evidence else 0,
        "assessed_as_of": as_of.isoformat(),
    }
    report["provider_assurance_state"] = "DOCUMENTED"
    report["platform_enforcement_state"] = "DOCUMENTED_NOT_LIVE_INSPECTED"
    report["automated_control_applicability"] = {
        "state": "REQUIRES_RELEVANT_SUBSCRIPTION_INVENTORY",
        "empty_inventory": "NOT_APPLICABLE",
        "api_or_permission_failure": "INDETERMINATE",
    }
    report["limitations"] = [
        "This report does not inspect Microsoft forwarding tables, tenant-isolated fabric internals, "
        "packets, MTU paths, or anti-spoofing implementation.",
        "Provider-owned and platform-enforced domains do not create findings or alter the tenant security score.",
        "Rule cross-references describe actual OSI behavior; Network-category rules at Layers 2, 4, "
        "and 7 are not counted as Layer 3 controls.",
    ]
    return report


def get_network_layer_assurance_report(as_of: date | None = None) -> dict[str, Any]:
    """Return the bundled Network Layer assurance report."""
    return build_report(load_catalog(), as_of=as_of)
