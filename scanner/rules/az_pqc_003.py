"""AZ-PQC-003: Key Vault certificates using classical algorithms."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-PQC-003"
RULE_NAME = "Key Vault Certificate Using Non-Quantum-Safe Signature Algorithm"
SEVERITY = "MEDIUM"
CATEGORY = "PostQuantum"
FRAMEWORKS = {
    "CIS": "8.9",
    "NIST": "PR.DS-2",
    "ISO27001": "A.8.24",
    "SOC2": "CC6.7",
}
DESCRIPTION = (
    "The Key Vault contains certificates signed using RSA or ECDSA algorithms. "
    "These classical signature schemes are vulnerable to Shor's algorithm on "
    "quantum computers. Certificates used for authentication, TLS, and code "
    "signing must be migrated to post-quantum safe signature algorithms such "
    "as ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)."
)
REMEDIATION = (
    "Audit all Key Vault certificates and identify those using RSA or ECDSA. "
    "Plan migration to post-quantum safe certificate authorities and signature "
    "algorithms. Include all certificates in your Cryptographic Bill of "
    "Materials. See playbooks/cli/fix_az_pqc_003.sh for remediation steps."
)
PLAYBOOK = "playbooks/cli/fix_az_pqc_003.sh"

logger = logging.getLogger(__name__)

_CLASSICAL_KEY_TYPES = {"RSA", "EC", "EC-HSM", "RSA-HSM"}
NCSC_GUIDANCE_URL = "https://www.ncsc.gov.uk/guidance/pqc-migration-timelines"
ENISA_GUIDANCE_URL = (
    "https://www.enisa.europa.eu/publications/post-quantum-cryptography-current-state-and-quantum-mitigation"
)


def _quantum_risk_score(algorithm_type: str) -> int:
    """Score RSA certificates above EC certificates for migration ordering."""
    return 8 if algorithm_type.upper().startswith("RSA") else 7


def _quantum_risk(algorithm_type: str) -> Dict[str, Any]:
    """Build the CBOM risk record for a classical certificate."""
    return {
        "quantum_risk_score": _quantum_risk_score(algorithm_type),
        "algorithm_type": algorithm_type,
        "internet_exposed": False,
        "harvest_now_decrypt_later_exposed": False,
        "hndl_risk_description": (
            "Recorded sessions may be exposed when this certificate authenticates "
            "classical key exchange, and future quantum attacks could forge signatures."
        ),
        "migration_priority": "MEDIUM",
        "recommended_target_algorithm": ("ML-DSA (NIST FIPS 204) or SLH-DSA (NIST FIPS 205)"),
        "nist_guidance_url": "https://csrc.nist.gov/pubs/fips/204/final",
        "ncsc_guidance_url": NCSC_GUIDANCE_URL,
        "enisa_guidance_url": ENISA_GUIDANCE_URL,
        "cbom_asset_type": "certificate",
    }


def _certificate_key_type(cert: Any) -> str:
    policy = getattr(cert, "policy", None)
    key_props = getattr(policy, "key_properties", None) if policy else None
    key_type = getattr(key_props, "key_type", None) if key_props else None
    return str(getattr(key_type, "value", None) or key_type or "")


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Scan Key Vault certificates for non-quantum-safe algorithms."""
    findings: List[Dict[str, Any]] = []

    vaults = azure_client.get_key_vaults()
    if vaults is None:
        logger.warning("AZ-PQC-003 skipped: unable to list Key Vaults.")
        return findings

    for vault in vaults:
        vault_id = getattr(vault, "id", "") or ""
        vault_name = getattr(vault, "name", "") or azure_client.parse_resource_id(vault_id).get("name", "")
        parsed = azure_client.parse_resource_id(vault_id)
        resource_group = parsed.get("resource_group", "")

        certs = azure_client.get_key_vault_certificates(vault_name)
        if certs is None:
            logger.warning("AZ-PQC-003: unable to list certificates for vault %s", vault_name)
            continue

        for cert in certs:
            key_type = _certificate_key_type(cert)
            if key_type.upper() in _CLASSICAL_KEY_TYPES:
                cert_id = getattr(cert, "id", "") or f"{vault_id}/certificates/{getattr(cert, 'name', '')}"
                cert_name = getattr(cert, "name", "") or cert_id.rstrip("/").split("/")[-1]
                quantum_risk = _quantum_risk(key_type)
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": SEVERITY,
                        "category": CATEGORY,
                        "resource_id": cert_id,
                        "resource_name": cert_name,
                        "resource_type": "Microsoft.KeyVault/vaults/certificates",
                        "description": DESCRIPTION,
                        "remediation": REMEDIATION,
                        "playbook": PLAYBOOK,
                        "frameworks": FRAMEWORKS,
                        "quantum_risk": quantum_risk,
                        "metadata": {
                            "resource_group": resource_group,
                            "vault_name": vault_name,
                            "key_type": key_type,
                            "quantum_risk": quantum_risk,
                        },
                    }
                )

    return findings
