# Python dependency locking

This implements the Python dependency slice of #304, not its deployment or
disaster-recovery acceptance criteria. The supported lock target is CPython 3.11
on Linux, matching CI and the container. Other Python versions/platforms are not
validated by these locks; use that environment to regenerate them.

`.python-version` declares the same minor version for native Render builds.
Before deployment, verify that no dashboard `PYTHON_VERSION` overrides it;
Render gives that environment variable precedence. No live settings are changed
by this PR. Python patch versions and base images remain separate update controls.

| Input maintained by contributors | Generated install file | Purpose |
| --- | --- | --- |
| `requirements.in` | `requirements.txt` | Runtime, including transitive dependencies |
| `requirements-dev.in` | `requirements-dev.txt` | Runtime plus pytest, coverage and ruff |
| `requirements-lock.in` | `requirements-lock.txt` | Isolated lock-generation tooling |

The development resolution is constrained by the runtime lock so tests use the
same runtime package versions. All three outputs pin versions and SHA-256 hashes.
Do not hand-edit generated files. Direct runtime pins were retained from the
existing requirements; previously open ranges and transitive packages are now
resolved explicitly. Hashes establish artifact integrity, not absence of vulnerabilities.

## Installation

Use a clean virtual environment. For production:

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements.txt
.venv/bin/python -m pip check
```

For development, substitute `requirements-dev.txt`. CI and the application
container use hash checking explicitly. Wheel-only installation avoids running
unlocked source-build dependencies; an unavailable wheel must fail rather than
silently fall back to building from source. Plain `pip install -r requirements.txt`
also enables hash checking because hashes are present, but use the explicit flags
above to enforce the full policy.

## Updating and checking

```bash
python3.11 -m venv .lock-tools
.lock-tools/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements-lock.txt
# Edit the relevant .in file, then regenerate all locks:
.lock-tools/bin/python scripts/lock_dependencies.py
# Verify without changing the checkout:
.lock-tools/bin/python scripts/lock_dependencies.py --check
```

Generation preserves existing pins where they satisfy the inputs. `--upgrade`
explicitly refreshes allowed versions; review that diff and run the full tests
and dependency audit before merging. Checking seeds a temporary directory with
committed locks, so new upstream releases alone do not cause drift failures. It
requires access to the package index and fails closed on resolution errors.
When changing the lock tool's own version, update the version guard in the script
and regenerate with that reviewed toolchain.

CI checks input/lock consistency within the existing rule-validation job, already
required by CI Summary. Backend tests install the development lock; production
does not install pytest, coverage, ruff or pip-tools. Security scanners retain
their independent tool environments; runtime SCA reads the resolved runtime lock.

## Remaining work under #304

These locks do not freeze the base image, OS packages, package-index availability,
or the container's existing pip/setuptools/wheel bootstrap. They also do not set
cloud topology, authorize deployment, create backups, define SLOs, or establish
release attestations. Those remain separate work. No existing vulnerability
exceptions are added or relaxed here. Lock generation alone is not security approval.
