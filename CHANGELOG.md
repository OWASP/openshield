# Changelog

All notable changes to OpenShield are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
OpenShield uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Ten evidence-rich enterprise network and perimeter controls `AZ-NET-018` through `AZ-NET-027` for issue #253, preserving API failures and incomplete data as indeterminate
- Azure Network Layer Assurance API with 20-domain coverage, network-rule classification, and authoritative IP forwarding and direct Internet route checks
- Azure Resource Graph inventory snapshots as the first OpenShield Evidence Graph foundation
- Azure Data Link Layer Assurance API with LLC and MAC coverage plus ExpressRoute Direct MACsec checks
- Azure public-cloud Physical Layer Assurance API with complete OSI and IEEE PHY domain, sublayer, and provider-evidence coverage
- Semgrep SAST integrated into GitHub Actions CI as an open-source, account-free complement to CodeQL
- OpenSSF Best Practices Passing Badge achieved with 100% of applicable Passing-level criteria completed
- Official live OpenSSF badge and verified project record added to project documentation
- CBOM endpoints with per-asset quantum risk scoring and migration guidance
- NCSC UK and ENISA post-quantum compliance framework mappings
- Harvest Now Decrypt Later exposure window calculation per cryptographic asset
- Deterministic Render deployment workflow for separate API and worker services
- Terraform configuration for Render, Vercel, and GitHub OIDC
- Database connection pool utilization and exhaustion telemetry (`openshield_db_pool_connections_*`) on `/metrics`

### Fixed

- High-severity CodeQL findings in Python and JavaScript code
- Security findings identified during Semgrep analysis
- Sensitive identity metadata removed from scanner debug logging
- `/ready` and `/metrics` rate-limited per source IP so the unauthenticated probe/scrape surface can no longer be used to exhaust the database connection pool

### Security

- Upgraded cryptography to 50.0.0 to address CVE-2026-69247
- AI provider errors no longer expose upstream response details
- Request body limits, AI rate limiting, and playbook path validation added
- GitHub Actions dependencies pinned to immutable commit SHAs
- JWTs must now carry an `exp` claim and a recognized `role`; a `viewer` token can no longer perform any write operation (scan trigger, AI endpoints), and `POST /api/scans/trigger` now checks `subscription_id` against an optional `OPENSHIELD_AUTHORIZED_SUBSCRIPTIONS` allowlist

## [0.3.0] - 2026-07-08

### Added

- Async scan execution with a background worker and PostgreSQL-backed job queue
- Scan state persistence and Render restart recovery with retry logic
- Structured JSON logging with request correlation via `X-Request-ID`
- Prometheus metrics for HTTP, scan, NVD, and LLM latency
- Separate `/health` liveness and `/ready` readiness probes
- Optional Sentry integration configured through `SENTRY_DSN`
- AZ-IDN-005 to AZ-IDN-009 Entra ID identity scanner rules
- AZ-PQC-001 to AZ-PQC-003 post-quantum cryptography scanner rules
- MockAzureClient offline rule regression test harness
- Azure scanner validation documentation framework
- CODEOWNERS with domain-based reviewer assignment
- Issue templates for bugs, features, and scanner rules
- Docker and Docker Compose support for self-hosted deployment
- Stale issue and pull request management workflow
- Dependency review workflow for high-severity vulnerabilities
- Release workflow triggered by version tags
- Docker image publishing to GHCR on release tags

### Fixed

- Duplicate CIS benchmark mappings across rules that shared control IDs
- TLS version comparison changed from lexicographic to numeric comparison
- Microsoft Graph pagination now follows `nextLink`
- Render automatic deployment replaced with a manual workflow dispatch

### Security

- Unsafe HTML rendering removed from website content updates
- Clear-text logging removed from identity scanner rules
- Vulnerable dependencies upgraded, including cryptography and wheel

## [0.2.3] - 2026-06-28

### Added

- CVE enrichment decoupled from the scan lifecycle into an on-demand endpoint
- OpenShield Learn portal updated with current architecture and rule coverage
- React Router dependency updated to 7.18.0

## [0.2.2] - 2026-06-15

### Added

- Live data wiring between the frontend and backend API
- Seven-page React dashboard for monitoring, discovery, prioritization, scanning, compliance, drift, and AI
- Project website at `openshield-website.vercel.app`
- JWT authentication production hardening

### Fixed

- Mock and demonstration data removed from the frontend
- Dashboard updated to serve persisted scan data end to end

## [0.2.0] - 2026-05-20

### Added

- RAG pipeline with ChromaDB and Azure security knowledge skills
- AI executive summary, prioritization, question answering, and remediation endpoints
- CVE correlation through NVD with CVSS scoring and CISA KEV exploit signals
- AZ-NET-012 to AZ-NET-016 network scanner rules
- AZ-IDN-004 privileged identity management scanner rule
- PostgreSQL-backed asynchronous scan persistence

## [0.1.0] - 2026-05-09

### Added

- Initial OpenShield release
- 20 Azure scanner rules across Storage, Network, Identity, Database, Compute, and Key Vault
- CIS Azure Benchmark, NIST CSF, ISO 27001, and SOC 2 mappings
- Flask REST API with JWT authentication
- CLI remediation playbooks for scanner rules
- Microsoft Sentinel integration with Log Analytics ingestion and KQL rules
- GitHub Actions continuous integration pipeline
- SBOM generation with Syft

[Unreleased]: https://github.com/openshield-org/openshield/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/openshield-org/openshield/releases/tag/v0.3.0
[0.2.3]: https://github.com/openshield-org/openshield/commit/3d6d7cc
[0.2.2]: https://github.com/openshield-org/openshield/commit/9575a33
[0.2.0]: https://github.com/openshield-org/openshield/commit/484eb9b
[0.1.0]: https://github.com/openshield-org/openshield/releases/tag/v0.1.0
