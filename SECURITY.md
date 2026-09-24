# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security vulnerabilities privately using
[GitHub's private security advisory feature](https://github.com/OWASP/openshield/security/advisories/new).

Please include:

- A description of the vulnerability and its potential impact
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

We follow coordinated disclosure. We will credit reporters in the release notes
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

OpenShield is a **read-only Azure security posture scanner**. Understanding its
scope helps set accurate expectations:

### What OpenShield does

- Reads Azure resource configuration via the Azure SDK using a provided
  credential (service principal or managed identity)
- Evaluates configuration against security rules and compliance frameworks
- Reports findings; it does not modify, remediate, or deploy anything

### What OpenShield does not guarantee

- OpenShield is a scanning and reporting tool, not a security enforcement
  mechanism. A clean scan result does not certify that a tenant is secure or
  compliant with any regulatory framework.
- Compliance framework mappings (CIS, NIST, ISO 27001, SOC 2) are provided as
  guidance only. They are not a substitute for a formal audit.
- OpenShield requires a credential with read access to your Azure subscription.
  Protect that credential according to your organization's secret management
  policy. OpenShield does not store, transmit, or log credentials beyond the
  running process.

### Out of scope

The following are not considered vulnerabilities in OpenShield:

- Findings that are false positives due to unsupported Azure API versions or
  preview features
- Rate limiting or throttling by the Azure ARM API
- Security posture of the Azure tenant being scanned (that is what the tool
  reports on, not a vulnerability in OpenShield itself)

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
| Branch protection | Required reviews and passing CI before merge |
