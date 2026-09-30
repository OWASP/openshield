# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security vulnerabilities privately using
[GitHub's private security advisory feature](https://github.com/OWASP/openshield/security/advisories/new).

> **Note for reporters:** Private vulnerability reporting must be enabled by an
> organisation owner (Settings > Code security > Private vulnerability reporting)
> before this link accepts reports from outside collaborators. If the link does
> not work, email **vishnu.ajith@owasp.org** directly.

Please include:

- A description of the vulnerability and its potential impact
- The affected component (scanner engine, REST API, auth logic, playbooks, sentinel)
- Steps to reproduce or a proof-of-concept (if available)
- Affected versions or components
- Any suggested fix (optional)

### Response timeline

| Stage | Target |
|---|---|
| Acknowledgement | Within 48 hours |
| Initial triage and severity assessment | Within 5 business days |
| Fix or mitigation | Depends on severity; critical issues within 14 days |
| Public disclosure | Coordinated with reporter after fix is merged |

We follow coordinated disclosure. We will credit reporters in
[`SECURITY_ACKNOWLEDGEMENTS.md`](../SECURITY_ACKNOWLEDGEMENTS.md)
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
| `api/` AI endpoints | Process untrusted finding text through LLM calls | Prompt injection, data leakage |
| Hardcoded secrets | Anywhere in the codebase | Any real credential committed to the repo |

### Out of scope

- Vulnerabilities in third-party dependencies — report those to the upstream maintainer
- Security issues in infrastructure you deploy OpenShield to (your Azure environment, your PostgreSQL instance)
- False-positive scan findings due to unsupported Azure API versions or preview features
- Rate limiting or throttling by the Azure ARM API
- Social engineering attacks
- Physical security

### Clarification on read-only behaviour

The `scanner/` component is read-only: it reads Azure configuration and does not
modify resources. The `playbooks/cli/` scripts are separate executables that a
human operator runs manually; they do modify Azure resources. The REST API and
sentinel components are active network services.

---

## Security Controls in This Repository

| Control | Implementation |
|---|---|
| Static analysis (SAST) | Semgrep, Bandit, CodeQL on every PR |
| Dependency scanning | Dependabot alerts + pip-audit in CI |
| Secret scanning | Gitleaks in CI |
| Container scanning | Trivy in CI |
| SBOM generation | Syft in CI |
| DCO sign-off | Enforced on every commit |
