# Input Validation Audit

This audit records every untrusted input boundary reviewed for OpenSSF Silver
issue #201. Validation occurs before values reach PostgreSQL, filesystem paths,
Azure/Sentinel integrations, subprocesses, or external AI providers.

## API-wide controls

- JSON request bodies are limited to 2 MiB by Flask.
- Protected routes require a bounded Bearer token and reject malformed tokens.
- Client request IDs accept only 1-128 letters, digits, `.`, `_`, `:` or `-`;
  invalid values are replaced with a server-generated UUID before logging.
- Validation failures return a fixed `400` response without reflecting
  exception details and without database or provider access. Authentication
  failures remain `401`.

## Boundary inventory

| Boundary | Accepted input | Enforcement |
|---|---|---|
| `POST /api/scans/trigger` | Optional JSON object; Azure subscription UUID | Object/field allowlist and canonical UUID validation before queue insertion |
| `GET /api/scans/<scan_id>` | Scan UUID | Canonical UUID validation before database access |
| `POST /api/scans/<scan_id>/enrich` | Scan UUID | Canonical UUID validation before lookup or background work |
| `GET /api/findings` | `severity`, `category`, `rule_id`, `scan_id` | Unknown/duplicate parameters rejected; severity/category allowlists; bounded rule pattern; UUID scan ID |
| Finding and playbook paths | Positive integer finding ID; stored rule ID | Positive ID check, strict rule pattern, resolved-path containment check |
| `GET /api/compliance/<framework>` | Named compliance framework | Existing framework allowlist; unknown frameworks rejected |
| AI POST routes | Provider, API key, optional model/question and findings | Field/provider allowlists; bounded strings; model pattern; maximum 1,000 object findings; bounded prompt fields |
| JWT header | HS256 Bearer token | 8 KiB header ceiling, exact prefix and PyJWT signature/expiry validation |
| Sentinel ingestion CLI | JSON file, scan ID, finding records and environment configuration | Existing regular `.json` file under 10 MiB; at most 1,000 object findings; bounded fields; severity/config format checks |
| Azure resource data | Management-plane SDK objects | Typed SDK accessors; failures preserved as unknown; no subprocess interpolation |
| Playbook selection | Rule ID derived from stored finding | Allowlisted identifier converted to a filename and constrained beneath `playbooks/cli` |
| Website content | Titles, excerpts, names and Markdown content authored in Decap CMS | No browser-side renderer remains: content is committed to the repository and rendered by Astro at build time, so nothing user-entered reaches a live DOM sink. Repository writes still require GitHub authorization, and the deployed pages are served under `script-src 'self'` with no inline script |

## Intentionally unrestricted text

AI questions, finding descriptions, remediation text and website article content
cannot use semantic allowlists without breaking legitimate use. They are instead
type checked, length bounded, kept out of SQL/file paths, and passed only through
parameterized or fixed-destination interfaces. AI prompts explicitly treat
findings as evidence and instruct providers not to invent unsupported facts.

## Regression evidence

`tests/test_input_validation.py` covers malformed JSON shapes, invalid and
oversized AI fields, injection-style identifiers, unknown and duplicated query
parameters, UUID enforcement, request-ID sanitization and authorization-header
limits. `tests/test_sentinel_input_validation.py` covers file, record, severity
and field-shape rejection. Existing authentication, error-exposure, playbook and
route tests protect prior behavior.

Re-run the audit when a route, query parameter, upload, CLI input, filesystem
selection, subprocess call, or external-provider integration is added.
