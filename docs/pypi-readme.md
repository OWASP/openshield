# OpenShield Azure scanner CLI

OpenShield is an open-source cloud security posture scanner for Azure. The `owasp-openshield` Python distribution provides the standalone `openshield` command. It runs the repository's Azure rules locally and prints findings without requiring the hosted API or PostgreSQL.

> **Package name:** Install `owasp-openshield`, then run `openshield`. The separate `openshield` distribution on PyPI belongs to an unrelated antivirus project.

## Quick start

Python 3.11 or later is required.

```sh
python -m pip install owasp-openshield
az login
openshield scan --subscription-id YOUR-AZURE-SUBSCRIPTION-UUID
openshield scan --subscription-id YOUR-AZURE-SUBSCRIPTION-UUID --format json
```

`AZURE_SUBSCRIPTION_ID` can replace the flag. The CLI uses Azure's `DefaultAzureCredential` chain, checks access to the subscription, and then runs the packaged rules. Give the identity read permissions to the subscription and any additional Graph or DevOps APIs used by the rules you rely on.

Results with findings exit `0` when the engine completed. Invalid configuration, authentication or subscription access failure, and incomplete rule execution exit `2`. Both report formats show failed rule IDs. Packaged remediation playbooks are references only; the CLI never executes them.

Many legacy rules do not yet provide complete per-resource evaluation evidence. A completed zero-finding run is not proof that every resource is compliant. Handle scan output as sensitive operational data because findings can contain Azure resource identifiers and configuration evidence.

Read the [full CLI guide](https://github.com/OWASP/openshield/blob/main/docs/cli.md), [source](https://github.com/OWASP/openshield), [security policy](https://github.com/OWASP/openshield/blob/main/.github/SECURITY.md), and [release verification guide](https://github.com/OWASP/openshield/blob/main/docs/release-verification.md).
