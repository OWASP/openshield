"""AZ-PQC-002: Key Vault keys using RSA or ECC algorithms."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-PQC-002"
RULE_NAME = "Key Vault Key Using Non-Quantum-Safe Algorithm"
SEVERITY = "HIGH"
CATEGORY = "PostQuantum"
FRAMEWORKS = {
    "CIS": "8.1",
    "NIST": "PR.DS-2",
    "ISO27001": "A.8.24",
    "SOC2": "CC6.7",
}
DESCRIPTION = (
    "The Key Vault contains keys using RSA or ECC algorithms which are vulnerable "
    "to quantum attacks using Shor's algorithm. A sufficiently powerful quantum "
    "computer can break RSA and ECC keys, compromising data encrypted or signed "
    "with these keys. Keys should be migrated to post-quantum safe algorithms "
    "such as those standardised by NIST in FIPS 203, FIPS 204, and FIPS 205."
)
REMEDIATION = (
    "Identify all RSA and ECC keys in Key Vault and plan migration to "
    "post-quantum safe alternatives. For signing use ML-DSA (FIPS 204). For key "
    "encapsulation use ML-KEM (FIPS 203). Document all keys requiring migration "
    "in a Cryptographic Bill of Materials (CBOM). See "
    "playbooks/cli/fix_az_pqc_002.sh for remediation steps."
)
PLAYBOOK = "playbooks/cli/fix_az_pqc_002.sh"

logger = logging.getLogger(__name__)

_CLASSICAL_KEY_TYPES = {"RSA", "EC", "EC-HSM", "RSA-HSM"}
NCSC_GUIDANCE_URL = "https://www.ncsc.gov.uk/guidance/pqc-migration-timelines"
ENISA_GUIDANCE_URL = (
    "https://www.enisa.europa.eu/publications/post-quantum-cryptography-current-state-and-quantum-mitigation"
)


def _quantum_risk_score(algorithm_type: str) -> int:
    """Score RSA above EC because of its common encryption and HNDL exposure."""
    return 9 if algorithm_type.upper().startswith("RSA") else 8


def _quantum_risk(algorithm_type: str) -> Dict[str, Any]:
    """Build the CBOM risk record for a classical asymmetric key."""
    return {
        "quantum_risk_score": _quantum_risk_score(algorithm_type),
        "algorithm_type": algorithm_type,
        "internet_exposed": False,
        "harvest_now_decrypt_later_exposed": True,
        "hndl_risk_description": (
            "Data protected by this key may already be collected for later decryption. "
            "The exposure depends on the key's use, data lifetime, and dependent services."
        ),
        "migration_priority": "HIGH",
        "recommended_target_algorithm": (
            "ML-KEM (NIST FIPS 203) for key encapsulation or ML-DSA (NIST FIPS 204) for signing"
        ),
        "nist_guidance_url": "https://csrc.nist.gov/pubs/fips/203/final",
        "ncsc_guidance_url": NCSC_GUIDANCE_URL,
        "enisa_guidance_url": ENISA_GUIDANCE_URL,
        "cbom_asset_type": "asymmetric_key",
    }


def _key_type_value(key: Any) -> str:
    key_type = getattr(key, "key_type", None)
    return str(getattr(key_type, "value", None) or key_type or "")


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Scan Key Vault keys for non-quantum-safe algorithm usage."""
    findings: List[Dict[str, Any]] = []

    vaults = azure_client.get_key_vaults()
    if vaults is None:
        logger.warning("AZ-PQC-002 skipped: unable to list Key Vaults.")
        return findings

    for vault in vaults:
        vault_id = getattr(vault, "id", "") or ""
        vault_name = getattr(vault, "name", "") or azure_client.parse_resource_id(vault_id).get("name", "")
        parsed = azure_client.parse_resource_id(vault_id)
        resource_group = parsed.get("resource_group", "")

        keys = azure_client.get_key_vault_keys(vault_name)
        if keys is None:
            logger.warning("AZ-PQC-002: unable to list keys for vault %s", vault_name)
            continue

        for key in keys:
            key_type = _key_type_value(key)
            if key_type.upper() in _CLASSICAL_KEY_TYPES:
                key_id = getattr(key, "id", "") or f"{vault_id}/keys/{getattr(key, 'name', '')}"
                key_name = getattr(key, "name", "") or key_id.rstrip("/").split("/")[-1]
                quantum_risk = _quantum_risk(key_type)
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": SEVERITY,
                        "category": CATEGORY,
                        "resource_id": key_id,
                        "resource_name": key_name,
                        "resource_type": "Microsoft.KeyVault/vaults/keys",
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
