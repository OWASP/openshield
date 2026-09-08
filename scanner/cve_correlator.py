"""
scanner/cve_correlator.py

Maps OpenShield findings to NVD keyword queries and merges CVE data
back into finding dicts.

The only function external code should call is enrich_findings().
Everything else is internal.
"""

import logging
from typing import Optional
from scanner.nvd_client import query_nvd, query_nvd_strict

logger = logging.getLogger(__name__)

# Maps rule_id prefixes (or full rule_ids) to NVD search keywords.
# Specific rule_ids take priority over prefix matches.
#
# How to pick a good keyword:
# - Specific enough to avoid noise ("Azure Storage" beats plain "Storage")
# - General enough to surface real CVEs ("Azure Key Vault" finds more
#   than "Azure Key Vault Purge Protection")
# - Test manually: https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<keyword>
#
# To add a new rule: add an entry here. No other file needs to change.

_RULE_CVE_KEYWORD_MAP: dict[str, str] = {
    # Storage
    "AZ-STOR": "Azure Storage Account",
    "AZ-STOR-003": "Azure Storage lifecycle management",
    # Key Vault
    "AZ-KV": "Azure Key Vault",
    "AZ-KV-002": "Azure Key Vault purge protection",
    # Compute
    "AZ-CMP": "Azure Virtual Machine",
    # Network
    "AZ-NET": "Azure Network Security Group",
    "AZ-NET-001": "Azure NSG open port",
    # Database
    "AZ-DB": "Azure SQL Database",
    # Identity
    "AZ-IDN": "Azure Active Directory",
    "AZ-IDN-001": "Azure RBAC privilege escalation",
    # Azure Kubernetes Service
    "AZ-AKS": "Azure Kubernetes Service",
    # App Service
    "AZ-APP": "Azure App Service",
}


def _get_nvd_keyword(rule_id: str) -> Optional[str]:
    """
    Return the best NVD keyword for a given rule_id.

    Tries exact match first, then walks back through prefix segments.
    Example: "AZ-STOR-003" tries "AZ-STOR-003", then "AZ-STOR".
    Returns None if no mapping found - caller skips NVD lookup.
    """
    if rule_id in _RULE_CVE_KEYWORD_MAP:
        return _RULE_CVE_KEYWORD_MAP[rule_id]

    parts = rule_id.split("-")
    for i in range(len(parts) - 1, 0, -1):
        prefix = "-".join(parts[:i])
        if prefix in _RULE_CVE_KEYWORD_MAP:
            return _RULE_CVE_KEYWORD_MAP[prefix]

    return None


def _enrich_single_finding(finding: dict) -> dict:
    """
    Add cve_references, cvss_score, and exploit_available to one finding.

    Args:
        finding: Dict with at least a "rule_id" key.

    Returns:
        The same dict with CVE fields added. Never raises.
    """
    rule_id = finding.get("rule_id", "")
    keyword = _get_nvd_keyword(rule_id)

    if not keyword:
        logger.debug("No NVD keyword mapping for rule_id: %s", rule_id)
        finding["cve_references"] = []
        finding["cvss_score"] = None
        finding["exploit_available"] = False
        return finding

    try:
        cves = query_nvd(keyword)

        finding["cve_references"] = cves

        # Top-level cvss_score: highest score across matched CVEs so callers
        # don't need to iterate cve_references to find the worst case.
        scores = [c["cvss_score"] for c in cves if c.get("cvss_score") is not None]
        finding["cvss_score"] = max(scores) if scores else None

        # exploit_available: True if any matched CVE is in CISA KEV
        finding["exploit_available"] = any(c.get("exploit_available") for c in cves)

    except Exception as e:
        # query_nvd should never raise, but if it does, don't crash the scan.
        logger.error("CVE enrichment failed for rule_id %s: %s", rule_id, e)
        finding["cve_references"] = []
        finding["cvss_score"] = None
        finding["exploit_available"] = False

    return finding


def enrich_findings(findings: list[dict]) -> list[dict]:
    """
    Add CVE data to a list of scan findings.

    This is the only public function in this module.

    Args:
        findings: List of finding dicts from the scanner or database.

    Returns:
        Same list with cve_references, cvss_score, and exploit_available
        added to each finding. Input order is preserved.
    """
    if not findings:
        return findings

    logger.info("Enriching %d findings with NVD CVE data...", len(findings))
    enriched = [_enrich_single_finding(f) for f in findings]
    logger.info("CVE enrichment complete.")
    return enriched


def enrich_finding_durable(finding: dict) -> dict:
    """Enrich one persisted finding and propagate retriable NVD failures."""
    keyword = _get_nvd_keyword(finding.get("rule_id", ""))
    if not keyword:
        finding["cve_references"] = []
        finding["cvss_score"] = None
        finding["exploit_available"] = False
        return finding
    cves = query_nvd_strict(keyword)
    finding["cve_references"] = cves
    scores = [c["cvss_score"] for c in cves if c.get("cvss_score") is not None]
    finding["cvss_score"] = max(scores) if scores else None
    finding["exploit_available"] = any(c.get("exploit_available") for c in cves)
    return finding
