# OpenShield Enterprise Rule Pack v1

## Status

This document is a researched backlog of 100 proposed enterprise security rules. It is not evidence that these rules are implemented. A rule becomes production-ready only after its collector, evaluation logic, tests, permission handling, evidence output, documentation, and live validation are complete.

The candidates are aligned with the Microsoft Cloud Security Benchmark, Microsoft Defender for Cloud recommendations, Azure service security baselines, Zero Trust principles, and control areas commonly covered by commercial CSPM and CNAPP platforms. They are not copied from a proprietary paid-product rule library.

PQC and CBOM are intentionally excluded from this pack.

## Required rule contract

Every rule must return one of the following states:

- `PASS`: sufficient evidence proves that the control is satisfied.
- `FAIL`: sufficient evidence proves that the control is not satisfied.
- `UNKNOWN`: the scanner could not establish the result, including permission or API failures.
- `NOT_APPLICABLE`: the control does not apply to the evaluated resource.

Every finding should include:

- Rule and resource identifiers
- Tenant, subscription, resource group, and region
- Observed and expected configuration
- Evidence source and collection timestamp
- Exposure, privilege, and data-sensitivity context
- Attack-path relevance
- Remediation guidance and required permissions
- Verified compliance references
- Confidence and reason for `UNKNOWN`

An API or authorization error must never produce a false `PASS`.

## Proposed rules

### 1. Identity and privileged access

1. Privileged users do not use phishing-resistant MFA.
2. Global Administrator roles are permanently assigned.
3. Privileged roles are assigned outside Privileged Identity Management.
4. Stale privileged accounts retain active access.
5. Emergency access accounts are missing or incorrectly protected.
6. Conditional Access does not block legacy authentication.
7. Conditional Access does not protect Azure management operations.
8. Risky-user or risky-sign-in protection is missing.
9. Workload identities are excluded from applicable access controls.
10. Privileged group membership is not appropriately governed.

### 2. Application identities and OAuth

11. An application has high-risk Microsoft Graph permissions.
12. An application has tenant-wide admin consent without an approved justification.
13. An unverified publisher application has privileged permissions.
14. Application credentials have an excessive validity period.
15. An application contains multiple active secrets without a documented need.
16. A stale application retains credentials or privileged permissions.
17. A service principal allows access without required user assignment.
18. A federated identity credential uses an overly broad subject or trust condition.
19. An application permits public-client authentication unnecessarily.
20. Application ownership contains inactive, guest, or otherwise unsuitable accounts.

### 3. Network, Private Link, and perimeter security

21. A private endpoint exists while public network access remains enabled.
22. A private endpoint connection is pending, rejected, or disconnected.
23. A private endpoint lacks the required private DNS zone association.
24. A private endpoint FQDN does not resolve through the expected private path.
25. A critical PaaS resource is internet-accessible without an approved exception.
26. Azure Firewall threat intelligence is not configured for alert-and-deny enforcement.
27. Application Gateway WAF is not operating in Prevention mode.
28. WAF diagnostic logging is not enabled.
29. WAF bot protection or an approved current managed rule set is missing.
30. An internet-facing application lacks an approved rate-limiting control.

### 4. Azure Functions, App Service, and API Management

31. A Function App does not enforce HTTPS-only access.
32. A Function App permits obsolete TLS versions.
33. A Function App permits public access without an approved requirement.
34. A Function App lacks a managed identity where supported.
35. Function App platform authentication is disabled where authentication is required.
36. Function App or App Service CORS configuration contains a wildcard origin.
37. App Service FTP or basic publishing authentication is enabled.
38. The SCM deployment endpoint is unnecessarily publicly accessible.
39. API Management developer portal authentication is insufficiently protected.
40. API Management lacks approved JWT validation, throttling, or equivalent gateway controls.

### 5. Data protection and databases

41. Storage account shared-key authorization remains enabled without an exception.
42. A storage account permits TLS below the approved minimum version.
43. Sensitive storage data is not protected with a required customer-managed key.
44. A critical blob container lacks an immutability policy.
45. Azure SQL does not enforce Microsoft Entra-only authentication where required.
46. SQL vulnerability assessment is not configured.
47. SQL auditing has insufficient coverage or retention.
48. Cosmos DB local authentication remains enabled without an approved requirement.
49. Cosmos DB public network access is enabled without an exception.
50. A managed cache permits public or non-TLS access.

### 6. AKS and container workload security

51. The AKS API server lacks approved IP restrictions.
52. An AKS cluster has no Kubernetes network policy.
53. Defender for Containers protection is disabled for an in-scope AKS cluster.
54. AKS secrets lack required Key Vault or KMS-backed protection.
55. Secrets Store CSI secret rotation is disabled.
56. Kubernetes workloads permit privileged containers.
57. Workloads permit unrestricted host network, host PID, or host IPC access.
58. Workloads permit unrestricted `hostPath` volumes.
59. Kubernetes `cluster-admin` access is assigned too broadly.
60. Workloads use untrusted registries, mutable tags, or the `latest` image tag.

### 7. Backup, ransomware resilience, and recovery

61. A critical resource is not protected by an approved backup policy.
62. Backup vault soft delete is disabled.
63. Enhanced soft delete is not enabled where required.
64. Backup vault immutability is not enabled.
65. Required backup immutability has not been locked.
66. Multi-user authorization through Resource Guard is missing.
67. Backup administration and Resource Guard permissions are not separated.
68. A backup vault permits unnecessary public network access.
69. Backup security alerts lack a monitored notification destination.
70. Recovery capability lacks evidence of a successful restore test within the required period.

### 8. Logging, detection, and security operations

71. Subscription activity logs are not exported to an approved central destination.
72. Required administrative, security, policy, or service-health log categories are missing.
73. A critical resource lacks required diagnostic settings.
74. Security logs have insufficient retention.
75. Security logs are stored only in a destination that can be modified by workload administrators.
76. Required Defender for Cloud protection is missing for a critical workload.
77. A high-risk Defender recommendation remains unresolved beyond its SLA.
78. A required Microsoft Sentinel data connector is disconnected or unhealthy.
79. Sentinel lacks required high-severity analytics coverage.
80. Security alerts have no monitored incident-response destination.

### 9. Governance, policy, and tenant control

81. A subscription is outside the approved management-group hierarchy.
82. A required security policy initiative is not assigned at the correct scope.
83. A mandatory preventive policy uses Audit instead of an approved enforcement effect.
84. A policy exemption lacks an owner, justification, or expiration date.
85. A critical production resource lacks an approved deletion lock.
86. A subscription has excessive Owner assignments.
87. Privileged access is assigned at an unnecessarily broad scope.
88. A resource provider is registered without a documented operational requirement.
89. A production resource lacks accountable ownership metadata.
90. Security configuration drift remains unresolved beyond the approved SLA.

### 10. DevSecOps, supply chain, and AI services

91. A CI/CD workflow uses long-lived Azure credentials instead of workload identity federation.
92. A CI workflow has unnecessarily broad token permissions.
93. A third-party workflow action is not pinned to an immutable commit.
94. Untrusted pull-request input can reach a privileged workflow context.
95. A protected branch permits unreviewed production changes.
96. A release artifact lacks an approved signature or provenance attestation.
97. Infrastructure deployment can bypass required security scanning.
98. An Azure OpenAI or Foundry resource permits unnecessary public access.
99. An AI service uses static keys where managed identity is available and required.
100. An AI resource lacks required diagnostic logging, encryption, or content-safety controls.

## Collection architecture

The 100 rules cannot be implemented correctly through a single Azure API.

| Evidence area | Preferred collector |
| --- | --- |
| Azure resource inventory and configuration | Azure Resource Graph |
| Configuration unavailable through ARG | Targeted Azure management SDK calls |
| Entra users, roles, applications, consent, and Conditional Access | Microsoft Graph |
| Kubernetes RBAC, pod specifications, and workload policies | Kubernetes API |
| GitHub and Azure DevOps security controls | Provider APIs and repository analysis |
| Runtime reachability and private DNS validation | Explicit, opt-in validation probes |

The intended flow is:

```text
ARG inventory
    -> rule applicability filtering
    -> Microsoft Graph, SDK, Kubernetes, or DevOps enrichment
    -> deterministic rule evaluation
    -> evidence-backed findings
    -> contextual risk and attack-path correlation
```

## Recommended delivery order

Implement the pack as five reviewable releases rather than one 100-rule pull request:

1. Private Link, perimeter, Functions, App Service, and API Management
2. Backup, recovery, logging, and detection
3. Identity, privileged access, application identities, and OAuth
4. Data protection, AKS, and container workload security
5. Governance, DevSecOps, supply chain, and AI services

Each release should include approximately 20 rules, rule documentation, unit and failure-path tests, permission tests, regression tests, and representative live Azure evidence.

## Production readiness gate

A proposed rule is ready only when all of the following are complete:

- The rule does not duplicate existing OpenShield behavior.
- Applicability and required permissions are documented.
- API errors and missing permissions return `UNKNOWN`.
- Positive, negative, malformed-data, and permission-failure tests pass.
- Evidence is stable, minimal, and useful to an operator.
- Severity is based on impact and context, not only the failed setting.
- Remediation is least-privilege and does not claim to be automatically safe.
- Compliance mappings use verified control identifiers rather than placeholders.
- A representative live validation has been recorded where practical.
- Documentation clearly distinguishes implemented behavior from future correlation features.

## Primary research sources

- [Microsoft Cloud Security Benchmark](https://learn.microsoft.com/en-us/security/benchmark/azure/)
- [Microsoft Defender for Cloud security recommendations](https://learn.microsoft.com/en-us/azure/defender-for-cloud/security-recommendations)
- [Microsoft Entra identity security guidance](https://learn.microsoft.com/en-us/azure/security/fundamentals/steps-secure-identity)
- [Azure Private Endpoint DNS guidance](https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-dns)
- [Application Gateway WAF overview](https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/ag-overview)
- [Azure Backup security overview](https://learn.microsoft.com/en-us/azure/backup/security-overview)
- [Azure Backup multi-user authorization](https://learn.microsoft.com/en-us/azure/backup/multi-user-authorization-tutorial)
- [Azure Policy regulatory compliance](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/regulatory-compliance)
