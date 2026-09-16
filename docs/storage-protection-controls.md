# Storage protection controls

The enterprise Storage controls in issue #261 use explicit opt-in metadata for
requirements that depend on business criticality. OpenShield does not infer that
every account or container needs a customer-managed key or immutability policy.

Use Azure resource tags as follows:

- `oshield:cmk-required=true` enables `AZ-STOR-008` for a storage account.
- `oshield:immutability-required=true` enables `AZ-STOR-009` for a storage account; all containers under that account are checked for an immutability policy.
- `oshield:entra-only-required=true` enables `AZ-DB-005` for a SQL server.
- `oshield:sql-va-required=true` enables `AZ-DB-006` for a SQL server.
- `oshield:sql-audit-required=true` enables `AZ-DB-007` for a SQL server.
- `oshield:cosmos-local-auth-disabled=true` enables `AZ-COSMOS-001`.
- `oshield:cosmos-public-access-disabled=true` enables `AZ-COSMOS-002`.
- `oshield:cache-private-tls-required=true` enables `AZ-CACHE-001`.
- `oshield:exception-approved=true` suppresses either control only when the
  organization has separately approved the exception.

Missing tags are not treated as proof that protection is required. Missing
encryption properties, unknown key sources, or an unavailable container API are
indeterminate and produce no finding. A finding is emitted only when the
requirement is explicitly enabled and an unsafe state is positively observed.

The tags are policy inputs, not evidence of approval by themselves; operators
must maintain the corresponding exception and criticality records outside the
scanner.
