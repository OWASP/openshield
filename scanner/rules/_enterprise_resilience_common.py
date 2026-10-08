"""Shared evaluators for the enterprise resilience rule packs."""

import logging
from typing import Any, Dict, List, Mapping

logger = logging.getLogger(__name__)

FRAMEWORKS = {"CIS": "TBD", "NIST": "PR.AC-5", "ISO27001": "A.8.20", "SOC2": "CC6.6"}


def _value(module: Any, name: str) -> Any:
    return module[name] if isinstance(module, Mapping) else getattr(module, name)


def finding(item: Mapping[str, Any], module: Any, resource_type: str, metadata: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "rule_id": _value(module, "RULE_ID"),
        "rule_name": _value(module, "RULE_NAME"),
        "severity": _value(module, "SEVERITY"),
        "category": _value(module, "CATEGORY"),
        "resource_id": item["id"],
        "resource_name": item["name"],
        "resource_type": resource_type,
        "description": _value(module, "DESCRIPTION"),
        "remediation": _value(module, "REMEDIATION"),
        "playbook": _value(module, "PLAYBOOK"),
        "frameworks": dict(_value(module, "FRAMEWORKS")),
        "metadata": dict(metadata),
    }


def scan_functions(client: Any, module: Any, field: str, unsafe: Any) -> List[Dict[str, Any]]:
    apps = client.get_function_app_security_posture()
    if apps is None:
        return []
    results = []
    for app in apps:
        value = app.get(field)
        if value is None:
            logger.warning("%s: %s is unknown for %s", _value(module, "RULE_ID"), field, app.get("name"))
            continue
        if unsafe(value):
            results.append(finding(app, module, "Microsoft.Web/sites", {field: value}))
    return results


RESOURCE_TYPES = {
    "storage": "Microsoft.Storage/storageAccounts",
    "sql": "Microsoft.Sql/servers",
    "postgresql": "Microsoft.DBforPostgreSQL/flexibleServers",
    "web": "Microsoft.Web/sites",
    "recovery": "Microsoft.RecoveryServices/vaults",
    "connection": "Microsoft.Network/privateEndpoints",
}


def scan_private(client: Any, module: Any, service: str) -> List[Dict[str, Any]]:
    posture = client.get_private_endpoint_posture()
    if posture is None:
        return []
    results = []
    for item in posture:
        if item.get("service") != service:
            continue
        if service == "connection":
            results.append(finding(item, module, RESOURCE_TYPES[service], {"connection_status": item.get("status")}))
            continue
        public = str(item.get("public_network_access") or "").lower()
        if public not in {"enabled", "disabled"}:
            logger.warning("%s: public network state unknown for %s", _value(module, "RULE_ID"), item.get("name"))
            continue
        required = set(item.get("required_groups") or [])
        approved = set(item.get("approved_groups") or [])
        if public == "enabled":
            results.append(
                finding(
                    item,
                    module,
                    RESOURCE_TYPES[service],
                    {
                        "public_network_access": item.get("public_network_access"),
                        "missing_private_link_groups": sorted(required - approved),
                    },
                )
            )
    return results


def scan_backup(client: Any, module: Any, unsafe: Any, metadata_fields: List[str]) -> List[Dict[str, Any]]:
    vaults = client.get_recovery_vault_security_posture()
    if vaults is None:
        return []
    results = []
    for vault in vaults:
        verdict = unsafe(vault)
        if verdict is None:
            logger.warning("%s: required state unknown for %s", _value(module, "RULE_ID"), vault.get("name"))
        elif verdict:
            results.append(
                finding(
                    vault, module, "Microsoft.RecoveryServices/vaults", {key: vault.get(key) for key in metadata_fields}
                )
            )
    return results
