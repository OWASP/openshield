# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

The published project contact is **vishnu.ajith@owasp.org**. Before sending
sensitive vulnerability details, request confirmation that this address is
monitored for security reports and that the recipient can accept the report.
Mailbox ownership, monitoring and the response targets below still require
maintainer confirmation; this policy does not establish those operational facts.

If maintainers enable GitHub private vulnerability reporting (PVR), you can report via
[GitHub's private security advisory feature](https://github.com/OWASP/openshield/security/advisories/new).

Please include:

- A description of the vulnerability and its potential impact
- The affected component (scanner engine, REST API, auth logic, playbooks, sentinel)
- Steps to reproduce or a proof-of-concept (if available)
- Affected versions or components
- Any suggested fix (optional)

### Response timeline

These are intended response targets, subject to confirmation of an operational
reporting channel. They are not a guarantee of mailbox monitoring or delivery.

| Stage | Target |
|---|---|
| Acknowledgement | Within 48 hours |
| Initial triage and severity assessment | Within 5 business days |
| Fix or mitigation | Depends on severity; critical issues within 14 days |
| Public disclosure | Coordinated with reporter after fix is merged |

We follow coordinated disclosure. We will credit reporters in
[SECURITY_ACKNOWLEDGEMENTS.md](https://github.com/OWASP/openshield/blob/main/SECURITY_ACKNOWLEDGEMENTS.md)
unless they prefer to remain anonymous.

---

## Supported Versions

We actively maintain the latest release on the `main` branch. Security fixes are
applied to the current release only. We do not backport fixes to older versions.

| Version | Supported |
|---|---|
| Latest (`main`) | Yes |
| Older releases | No |

---

## Security Scope

OpenShield is a multi-component security tool. Understanding what each component
does helps reporters accurately scope their findings.

### In scope

| Component | What it does | Security relevance |
|---|---|---|
| `api/` | REST API with JWT/OIDC authentication and role-based access control | Auth bypass, privilege escalation, input validation, JWT handling |
| `scanner/` | Reads Azure resource configuration via the Azure SDK; does not write | Credential handling, cross-tenant isolation, output integrity |
| `playbooks/cli/` | Remediation scripts that modify Azure resources when run manually | Command injection, privilege escalation, unsafe Azure mutations |
| `sentinel/` | Signs and uploads scan data to Azure Log Analytics via HMAC | HMAC signing, credential handling, data integrity |
| `ai/` | RAG pipeline (embedding, retrieval, chunking) invoked by the API AI endpoints | Prompt injection, data leakage, path traversal on document loading |
| `compliance/` | Compliance framework mappings consumed by the API and scanner | Logic errors that incorrectly map controls, suppressing true positives |
| `frontend/` | React dashboard that displays scan results and compliance reports | XSS, CSRF, insecure API consumption, auth state handling |
| `website/` | Astro project website and documentation | XSS, content injection, dependency vulnerabilities |
| Hardcoded secrets | Anywhere in the codebase | Any real credential committed to the repo |

### Out of scope

- Vulnerabilities solely in third-party dependencies without an OpenShield-specific impact: report those to the upstream maintainer. Report exploitable integration or deployment issues in the components listed above through the OpenShield reporting channel.
- Security issues in infrastructure you deploy OpenShield to (your Azure environment, your PostgreSQL instance)
- False-positive scan findings due to unsupported Azure API versions or preview features
- Rate limiting or throttling by the Azure ARM API
- Social engineering attacks
- Physical security

### Clarification on read-only behavior

The `scanner/` component is read-only: it reads Azure configuration and does not
modify resources. The `playbooks/cli/` scripts are separate executables that a
human operator runs manually; they do modify Azure resources. The REST API and
sentinel components are active network services.

---

## Security Controls in This Repository

| Control | Implementation |
|---|---|
| Static analysis (SAST) | Semgrep, Bandit in CI + CodeQL (separate workflow) on every PR |
| Dependency scanning | Dependabot alerts (GitHub) + pip-audit in CI |
| Secret scanning | Gitleaks in CI |
| Container scanning | Trivy in CI |
| SBOM generation | Syft in CI |
| DCO sign-off | DCO check runs on every pull request |
