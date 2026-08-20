"""Read-only Azure governance evidence collection and policy loading."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import requests
from azure.core.exceptions import AzureError

ARM_ENDPOINT = "https://management.azure.com"


@dataclass(frozen=True)
class GovernancePolicy:
    approved_management_group_ids: frozenset[str]
    required_policy_initiatives: tuple[Mapping[str, str], ...]
    preventive_policy_definition_ids: frozenset[str]
    allowed_preventive_effects: frozenset[str]
    production_resource_types: frozenset[str]
    production_tag: str
    production_tag_values: frozenset[str]
    maximum_subscription_owners: int
    privileged_role_definition_ids: frozenset[str]
    approved_privileged_scopes: frozenset[str]
    approved_provider_namespaces: frozenset[str]
    ownership_tags: frozenset[str]
    drift_sla_days: int
    excluded_resource_ids: frozenset[str]


_FIELDS = {
    "approved_management_group_ids",
    "required_policy_initiatives",
    "preventive_policy_definition_ids",
    "allowed_preventive_effects",
    "production_resource_types",
    "production_tag",
    "production_tag_values",
    "maximum_subscription_owners",
    "privileged_role_definition_ids",
    "approved_privileged_scopes",
    "approved_provider_namespaces",
    "ownership_tags",
    "drift_sla_days",
    "excluded_resource_ids",
}


def _strings(raw: Mapping[str, Any], field: str) -> frozenset[str]:
    values = raw[field]
    if not isinstance(values, list) or any(not isinstance(item, str) or not item.strip() for item in values):
        raise ValueError(f"{field} must be a list of non-empty strings")
    return frozenset(item.strip().lower() for item in values)


def load_governance_policy(path: str | Path) -> GovernancePolicy:
    """Load strict organisation-owned governance expectations."""
    with Path(path).open(encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, dict) or set(raw) != _FIELDS:
        raise ValueError("governance policy has missing or unsupported fields")
    initiatives = raw["required_policy_initiatives"]
    if not isinstance(initiatives, list):
        raise ValueError("required_policy_initiatives must be a list")
    normalised_initiatives = []
    for item in initiatives:
        if not isinstance(item, dict) or set(item) != {"definition_id", "scope"}:
            raise ValueError("each required policy initiative needs definition_id and scope")
        if any(not isinstance(item[key], str) or not item[key].strip() for key in item):
            raise ValueError("initiative definition_id and scope must be non-empty strings")
        normalised_initiatives.append({key: value.strip().lower() for key, value in item.items()})
    for field in ("maximum_subscription_owners", "drift_sla_days"):
        if not isinstance(raw[field], int) or isinstance(raw[field], bool) or raw[field] <= 0:
            raise ValueError(f"{field} must be a positive integer")
    if not isinstance(raw["production_tag"], str) or not raw["production_tag"].strip():
        raise ValueError("production_tag must be a non-empty string")
    return GovernancePolicy(
        approved_management_group_ids=_strings(raw, "approved_management_group_ids"),
        required_policy_initiatives=tuple(normalised_initiatives),
        preventive_policy_definition_ids=_strings(raw, "preventive_policy_definition_ids"),
        allowed_preventive_effects=_strings(raw, "allowed_preventive_effects"),
        production_resource_types=_strings(raw, "production_resource_types"),
        production_tag=raw["production_tag"].strip().lower(),
        production_tag_values=_strings(raw, "production_tag_values"),
        maximum_subscription_owners=raw["maximum_subscription_owners"],
        privileged_role_definition_ids=_strings(raw, "privileged_role_definition_ids"),
        approved_privileged_scopes=_strings(raw, "approved_privileged_scopes"),
        approved_provider_namespaces=_strings(raw, "approved_provider_namespaces"),
        ownership_tags=_strings(raw, "ownership_tags"),
        drift_sla_days=raw["drift_sla_days"],
        excluded_resource_ids=_strings(raw, "excluded_resource_ids"),
    )


class GovernanceCollector:
    """Collect governance control-plane metadata without changing Azure state."""

    def __init__(self, credential: Any, subscription_id: str, *, session: Any = requests) -> None:
        self.credential = credential
        self.subscription_id = subscription_id
        self.session = session
        self.scope = f"/subscriptions/{subscription_id}"

    def _headers(self) -> dict[str, str]:
        token = self.credential.get_token("https://management.azure.com/.default")
        return {"Authorization": f"Bearer {token.token}", "Content-Type": "application/json"}

    def _get_all(self, path: str) -> list[dict[str, Any]] | None:
        url = path if path.startswith("https://") else f"{ARM_ENDPOINT}{path}"
        items: list[dict[str, Any]] = []
        try:
            while url:
                response = self.session.get(url, headers=self._headers(), timeout=30)
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, dict):
                    return None
                values = payload.get("value", [])
                if not isinstance(values, list):
                    return None
                items.extend(item for item in values if isinstance(item, dict))
                next_link = payload.get("nextLink")
                url = next_link if isinstance(next_link, str) and next_link.startswith(ARM_ENDPOINT) else ""
            return items
        except (requests.RequestException, AzureError, ValueError, TypeError):
            return None

    def _post_graph(self, query: str) -> list[dict[str, Any]] | None:
        items: list[dict[str, Any]] = []
        options: dict[str, Any] = {"resultFormat": "objectArray"}
        try:
            while True:
                response = self.session.post(
                    f"{ARM_ENDPOINT}/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01",
                    headers=self._headers(),
                    json={"subscriptions": [self.subscription_id], "query": query, "options": options},
                    timeout=30,
                )
                response.raise_for_status()
                payload = response.json()
                data = payload.get("data")
                if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
                    return None
                items.extend(data)
                skip_token = payload.get("$skipToken")
                if not isinstance(skip_token, str) or not skip_token:
                    return items
                options = {"resultFormat": "objectArray", "$skipToken": skip_token}
        except (requests.RequestException, AzureError, ValueError, TypeError, AttributeError):
            return None

    def _post_values(self, path: str) -> list[dict[str, Any]] | None:
        url = f"{ARM_ENDPOINT}{path}"
        items: list[dict[str, Any]] = []
        try:
            while url:
                response = self.session.post(url, headers=self._headers(), json={}, timeout=30)
                response.raise_for_status()
                payload = response.json()
                values = payload.get("value")
                if not isinstance(values, list) or not all(isinstance(item, dict) for item in values):
                    return None
                items.extend(values)
                next_link = payload.get("@odata.nextLink", payload.get("nextLink"))
                url = next_link if isinstance(next_link, str) and next_link.startswith(ARM_ENDPOINT) else ""
            return items
        except (requests.RequestException, AzureError, ValueError, TypeError, AttributeError):
            return None

    def collect(self) -> dict[str, Any]:
        """Return independently nullable evidence sets so partial access stays UNKNOWN."""
        policy_api = "2023-04-01"
        authorization_api = "2022-04-01"
        resources = self._post_graph("Resources | project id, name, type, resourceGroup, tags, subscriptionId")
        hierarchy_rows = self._post_graph(
            "ResourceContainers | where type =~ 'microsoft.resources/subscriptions' "
            "| project properties.managementGroupAncestorsChain"
        )
        return {
            "scope": self.scope,
            "hierarchy": hierarchy_rows,
            "policy_assignments": self._get_all(
                f"{self.scope}/providers/Microsoft.Authorization/policyAssignments?api-version={policy_api}&%24filter=atScope()"
            ),
            "policy_exemptions": self._get_all(
                f"{self.scope}/providers/Microsoft.Authorization/policyExemptions"
                "?api-version=2022-07-01-preview&%24filter=atScope()"
            ),
            "role_assignments": self._get_all(
                f"{self.scope}/providers/Microsoft.Authorization/roleAssignments?api-version={authorization_api}&%24filter=atScope()"
            ),
            "policy_definitions": self._get_all(
                "/providers/Microsoft.Authorization/policyDefinitions?api-version=2023-04-01"
            ),
            "locks": self._get_all(f"{self.scope}/providers/Microsoft.Authorization/locks?api-version=2016-09-01"),
            "providers": self._get_all(f"{self.scope}/providers?api-version=2021-04-01"),
            "resources": resources,
            "policy_states": self._post_values(
                f"{self.scope}/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults?api-version=2019-10-01"
            ),
        }
