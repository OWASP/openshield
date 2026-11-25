"""Azure DevOps API wrapper for Supply Chain pipeline/service-connection rules.

Separate from AzureClient because Azure DevOps lives at dev.azure.com, not
Azure Resource Manager, and needs its own configuration (organization URL,
project name) that an ARM subscription ID does not carry. Reuses the same
DefaultAzureCredential already used for the Azure subscription, scoped to
Azure DevOps' well-known Entra ID resource ID, so no separate stored
credential (e.g. a PAT) is required.
"""

import logging
from typing import Any, List, Optional

logger = logging.getLogger(__name__)

# Well-known Entra ID resource ID for Azure DevOps. Used as the OAuth scope
# when requesting a token from the same credential AzureClient already uses.
AZURE_DEVOPS_RESOURCE_ID = "499b84ac-1321-427f-aa17-267ca6975798"

_UNSET = object()


class IntegrationNotConfigured(Exception):
    """Raised when Azure DevOps is not configured for this scan.

    Kept distinct from a failed call (which returns ``None``) so a rule can
    report NOT_APPLICABLE for "not set up" and ERROR for "set up but
    unreachable".
    """


class DevOpsClient:
    """Wraps the Azure DevOps Service Endpoint API for pipeline scan rules.

    Instantiate once per scan (alongside AzureClient) and share across all
    Supply Chain rule modules that need Azure DevOps data. Every method logs
    on failure and returns None so an unreachable or unconfigured Azure
    DevOps organization never crashes the scan engine.
    """

    def __init__(self, organization_url: str, project: str, credential: Optional[Any] = None) -> None:
        """
        Args:
            organization_url: e.g. "https://dev.azure.com/my-org".
            project: The Azure DevOps project name or ID to scan.
            credential: A TokenCredential. Defaults to DefaultAzureCredential,
                matching AzureClient's default.
        """
        self.organization_url = organization_url
        self.project = project
        if credential is None:
            from azure.identity import DefaultAzureCredential

            credential = DefaultAzureCredential()
        self.credential = credential
        self._service_endpoints_cache: Any = _UNSET

    def _get_connection(self) -> Any:
        from azure.devops.connection import Connection
        from azure.devops.credentials import OAuthTokenAuthentication

        access_token = self.credential.get_token(f"{AZURE_DEVOPS_RESOURCE_ID}/.default")
        auth = OAuthTokenAuthentication(AZURE_DEVOPS_RESOURCE_ID, {"access_token": access_token.token})
        return Connection(base_url=self.organization_url, creds=auth)

    def get_service_endpoints(self) -> Optional[List[Any]]:
        """Return pipeline service connections for the configured project.

        Cached for the lifetime of this client because both AZ-SC service
        connection rules evaluate the same project-level collection.

        Returns:
            A list (including an empty list) when Azure DevOps responds
            successfully, or ``None`` when auth, permissions, or the SDK
            prevent the collection from being evaluated. Callers must never
            interpret ``None`` as a compliant result.
        """
        if self._service_endpoints_cache is not _UNSET:
            return self._service_endpoints_cache

        try:
            connection = self._get_connection()
            client = connection.clients_v7_1.get_service_endpoint_client()
            self._service_endpoints_cache = list(client.get_service_endpoints(project=self.project))
        except Exception as exc:
            logger.error("get_service_endpoints failed for project %s: %s", self.project, exc)
            self._service_endpoints_cache = None
        return self._service_endpoints_cache
