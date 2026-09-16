# Private Link and private DNS controls

`AZ-NET-018` through `AZ-NET-021` implement the first delivery tranche of issue #253. They use the Azure Resource Manager Private Endpoint inventory, connection state, Private DNS zone groups, custom DNS configuration, and service-specific public-access properties.

The controls distinguish four outcomes: a finding is `FAIL`; successful evaluation without a finding is `PASS`; empty Private Endpoint inventory is `NOT_APPLICABLE`; and API failures, unsupported target types, absent state, or incomplete DNS evidence are `UNKNOWN` and never create a finding. The current scanner persists failures rather than pass records, so `UNKNOWN` and `NOT_APPLICABLE` are emitted to scanner logs while evidence for failures is included in finding metadata.

Public-access evaluation is deliberately limited to target types with authoritative service-specific management APIs: Storage accounts, Key Vaults, and Azure SQL logical servers. Other target types are unknown until a service collector is added. AZ-NET-021 evaluates only the `customDnsConfigs` returned for the Private Endpoint. Those values describe Azure's expected DNS configuration; they do not prove effective resolution from a workload VNet or on-premises resolver, whose DNS context may differ from the scanner host.

Required permissions are `Microsoft.Network/privateEndpoints/read`, `Microsoft.Network/privateEndpoints/privateDnsZoneGroups/read`, and read permission on the target PaaS resource. Remediation playbooks require an operator to validate connectivity before disabling access or modifying DNS.

## Enterprise perimeter controls

The remaining issue controls are implemented by `AZ-NET-022` through `AZ-NET-027`:

- Critical PaaS public exposure covers Storage accounts, Key Vaults, Azure SQL logical servers, PostgreSQL servers, and App Service. Exceptions are exact, case-insensitive resource IDs in `OPENSHIELD_PUBLIC_PAAS_EXCEPTIONS`; partial matches are never accepted.
- Azure Firewall threat intelligence must be `Deny`.
- An enabled Application Gateway WAF must use Prevention mode and export every diagnostic log category supported by its SKU. WAF v1 requires access, performance, and firewall logs; WAF_v2 requires access and firewall logs, while performance telemetry is supplied through Azure Monitor metrics.
- Application Gateway WAF policies must include OWASP 3.2 or Microsoft Default Rule Set 2.1 or later plus Microsoft Bot Manager Rule Set 1.0 or later.
- Public Application Gateways with WAF enabled must have an enabled `RateLimitRule` in the associated WAF policy.

Each PaaS service inventory is independent. A permission failure for one service is `UNKNOWN` for that service and does not suppress valid findings from another. Application Gateway or WAF policy inventory failures similarly remain `UNKNOWN`. Empty service inventories are `NOT_APPLICABLE`. Rate limiting is deliberately limited to public Application Gateways because the repository currently has no authoritative inventory collector for Front Door, API Management, or third-party edge controls; those services remain unknown rather than being inferred from incomplete inventory.
