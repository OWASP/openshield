# AKS and Kubernetes Security Rules

OpenShield evaluates Azure Kubernetes Service across three evidence planes:

- Azure Resource Manager for cluster configuration and add-on state.
- Microsoft Defender for Cloud for the Containers protection plan.
- The Kubernetes API for namespaces, network policies, workloads, pods, and cluster role bindings.

The original six AKS rules remain control-plane-only. The issue #255 extension adds fifteen independently remediable controls so each domain and subdomain has its own rule, finding, mapping, test coverage, and playbook.

## Coverage

| Domain | Subdomain | Rule | Control |
|---|---|---|---|
| Control plane | Endpoint isolation | `AZ-AKS-001` | Private API server endpoint |
| Identity | Local authentication | `AZ-AKS-002` | Local account disablement |
| Identity | Cluster identity | `AZ-AKS-003` | Control-plane managed identity |
| Identity | Workload identity | `AZ-AKS-004` | OIDC issuer and Workload Identity |
| Governance | Admission policy | `AZ-AKS-005` | Azure Policy add-on |
| Node security | Patch management | `AZ-AKS-006` | Managed node OS security upgrades |
| Control plane | Public endpoint restriction | `AZ-AKS-007` | Approved API server IP ranges |
| Network security | Policy engine | `AZ-AKS-008` | Azure, Calico, or Cilium network policy engine |
| Network security | Namespace segmentation | `AZ-AKS-009` | NetworkPolicy presence in eligible namespaces |
| Threat protection | Managed detection | `AZ-AKS-010` | Defender for Containers subscription plan |
| Secret protection | Encryption and external secrets | `AZ-AKS-011` | Key Vault CSI or Key Vault KMS protection |
| Secret protection | Credential lifecycle | `AZ-AKS-012` | Secrets Store CSI automatic rotation |
| Workload isolation | Privilege boundary | `AZ-AKS-013` | Privileged application and init containers |
| Workload isolation | Network namespace | `AZ-AKS-014` | Host network access |
| Workload isolation | Process namespace | `AZ-AKS-015` | Host PID access |
| Workload isolation | IPC namespace | `AZ-AKS-016` | Host IPC access |
| Workload isolation | Node filesystem | `AZ-AKS-017` | HostPath volumes |
| Authorization | Cluster privilege | `AZ-AKS-018` | Approved cluster-admin subjects |
| Software supply chain | Registry trust | `AZ-AKS-019` | Approved image registry prefixes |
| Software supply chain | Floating release | `AZ-AKS-020` | Latest and implicit latest tags |
| Software supply chain | Image immutability | `AZ-AKS-021` | SHA-256 digest pinning |

## Organization policy

Rules that require an approved scope or allowlist load a strict JSON policy from `OPENSHIELD_AKS_SECURITY_POLICY`. Start from `config/aks-security-policy.example.json` and keep the deployed policy outside the repository if it contains internal network or registry names.

The policy defines:

- Approved API server CIDR ranges.
- Trusted registry and repository prefixes.
- Approved `cluster-admin` Groups and Users in `Kind:name` form.
- Approved `cluster-admin` ServiceAccounts in `ServiceAccount:namespace:name` form.
- Namespaces excluded from workload evaluation.
- Whether image digest pinning is required.

Missing, malformed, or incomplete policy makes the four policy-dependent controls UNKNOWN: API server IP restrictions
(`AZ-AKS-007`), approved cluster-admin subjects (`AZ-AKS-018`), trusted registry prefixes (`AZ-AKS-019`), and required
image digest pinning (`AZ-AKS-021`). The other controls continue to evaluate available ARM and Kubernetes evidence.
When a valid policy is present, its `excluded_namespaces` safeguard applies to every workload control. OpenShield does
not invent organization-specific allowlists or defaults.

## Kubernetes credentials

Set `OPENSHIELD_AKS_KUBECONFIG` to a read-only kubeconfig. Set `OPENSHIELD_AKS_KUBECONFIG_CONTEXTS` to a strict JSON mapping from each complete AKS resource ID to its kubeconfig context name. Start from `config/aks-kubeconfig-contexts.example.json`.

Resource IDs are matched case-insensitively. Each context may map to only one AKS resource ID, and every scanned cluster must have an explicit entry. Missing, malformed, unresolved, or ambiguous mappings remain UNKNOWN. This prevents clusters with the same resource-group-scoped name from sharing evidence accidentally.

The scanner never records kubeconfig content, tokens, Kubernetes Secrets, or environment variable values.

The Kubernetes identity needs read-only access equivalent to:

```text
get,list namespaces
get,list pods
get,list deployments,statefulsets,daemonsets.apps
get,list jobs,cronjobs.batch
get,list networkpolicies.networking.k8s.io
get,list clusterrolebindings.rbac.authorization.k8s.io
```

The Azure identity needs:

```text
Microsoft.ContainerService/managedClusters/read
Microsoft.Security/pricings/read
```

## Evidence states

The scan engine represents FAIL as a finding and represents PASS, UNKNOWN, and NOT_APPLICABLE as an empty finding list with an explicit log entry.

- `FAIL` requires positive evidence of the unsafe setting.
- `UNKNOWN` is used for missing or invalid policy on the four policy-dependent controls, missing kubeconfig, stopped or unreachable clusters, authorization errors, malformed identity, and unavailable ARM or Defender evidence.
- `PARTIAL` preserves positive evidence from reachable namespaces but never treats missing namespaces as compliant.
- `NOT_APPLICABLE` is used when no AKS cluster, eligible namespace, workload, CSI provider, or relevant object exists.

Every FAIL includes cluster, namespace, workload, container, image, subject, role, source, collection timestamp, observed value, expected value, required permissions, severity, confidence, and a null UNKNOWN reason.

## Remediation safety

Every rule has a matching `playbooks/cli/fix_az_aks_<id>.sh` file. The playbooks use the same review gate as other enterprise controls. Safe Azure changes are automated only after account, target, and impact confirmation. Kubernetes manifest, RBAC, and network policy changes remain operator-reviewed because a generic automatic patch could interrupt production or remove break-glass access.

For `AZ-AKS-011`, enabling the Key Vault Secrets Store CSI add-on is only a prerequisite. It does not migrate an
existing workload or protect native Kubernetes Secret references. To use the CSI remediation path, configure Workload
Identity and least-privilege Key Vault access, create and test a `SecretProviderClass`, mount the
`secrets-store.csi.k8s.io` volume, and remove the workload's native Secret volume, projected Secret, `env`, and
`envFrom` references. Restart and test the workload, then verify that no native Secret references remain. If native
Kubernetes Secrets must remain, enable and validate AKS Key Vault KMS instead. Re-run OpenShield only after the chosen
path is complete.

## Compliance note

The repository models CIS Microsoft Azure Foundations Benchmark 2.0.0. Only Defender for Containers has a direct control in that benchmark. Kubernetes data-plane controls are explicitly recorded as `N/A-AKS-*` rather than being assigned unsupported CIS Kubernetes Benchmark identifiers. NIST CSF 1.1, ISO/IEC 27001:2013, and SOC 2 mappings follow the framework versions already used by OpenShield.

## Authoritative references

- [AKS API server authorized IP ranges](https://learn.microsoft.com/azure/aks/api-server-authorized-ip-ranges)
- [AKS network policies](https://learn.microsoft.com/azure/aks/use-network-policies)
- [Defender for Containers](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-containers-introduction)
- [Azure Key Vault provider for Secrets Store CSI](https://learn.microsoft.com/azure/aks/csi-secrets-store-driver)
- [AKS Key Management Service](https://learn.microsoft.com/azure/aks/use-kms-etcd-encryption)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes images](https://kubernetes.io/docs/concepts/containers/images/)
