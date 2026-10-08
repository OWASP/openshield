# OpenShield Security Requirements

## Security objectives

OpenShield must:

- authenticate state-changing API operations and fail closed in production when
  the JWT secret is missing, weak or set to the development default;
- request only the Azure management-plane and Microsoft Graph permissions
  documented for enabled checks;
- avoid collecting secrets, credentials, application settings, customer data or
  workload contents when configuration metadata is sufficient;
- validate restricted untrusted inputs using allowlists, length limits and
  typed parsing before they reach files, databases, subprocesses or external
  services;
- preserve API and permission failures as unknown rather than reporting false
  compliance;
- protect network communication using HTTPS/TLS with certificate verification;
- keep dependencies, workflows and release contents reviewable and
  machine-inventoried;
- log security-relevant failures without disclosing credentials or sensitive
  provider responses.

## Expected deployment controls

Operators are responsible for TLS termination, database access control, secret
storage, log retention, backup and recovery, Azure least-privilege role
assignment, and restricting administrative access to trusted users and
networks. Production deployments must use unique secrets and supported
dependencies.

## Security limitations

OpenShield is a posture assessment aid, not a penetration test, formal audit or
guarantee of security. A clean scan does not prove that an Azure environment is
secure. Rules cover documented configuration states and may be limited by API
permissions, service tiers, Azure API behavior and organizational context.
Remediation playbooks can affect availability and require operator review.

OpenShield does not claim that its framework mappings constitute certification
or complete benchmark coverage. Compliance reports are versioned technical
evidence coverage against a specific mapping-pack revision, not an audit
opinion; see `docs/compliance-mapping-pack.md` for supported framework
editions, mapping-pack versioning, and what is excluded from each framework's
pass-rate denominator. Unsupported versions receive no guaranteed security
fixes.

## Verification evidence

The security policy, architecture, assurance case, automated test suite, SAST,
secret scanning, dependency review, SBOM generation and container scanning form
the public evidence for these requirements. Known defects must be tracked and
resolved through GitHub issues or private advisories as appropriate.

The reviewed input boundaries, limits, allowlists and intentional free-text
exceptions are recorded in `docs/input-validation-audit.md`.
