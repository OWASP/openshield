"""Install both distribution artifacts outside the checkout and inspect CLI contents."""

import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path


def run(*args, cwd, env=None):
    subprocess.run(args, cwd=cwd, env=env, check=True)


def main() -> None:
    artifacts = Path(sys.argv[1]).resolve()
    files = list(artifacts.glob("owasp_openshield-*.whl")) + list(artifacts.glob("owasp_openshield-*.tar.gz"))
    if len(files) != 2:
        raise SystemExit(f"Expected one wheel and one sdist, found {files}")
    with tempfile.TemporaryDirectory(prefix="openshield-package-") as temporary:
        root = Path(temporary)
        for index, artifact in enumerate(files):
            target = root / str(index)
            target.mkdir()
            environment = target / "environment"
            venv.EnvBuilder(with_pip=True).create(environment)
            bin_dir = environment / ("Scripts" if os.name == "nt" else "bin")
            python = bin_dir / ("python.exe" if os.name == "nt" else "python")
            openshield = bin_dir / ("openshield.exe" if os.name == "nt" else "openshield")
            run(str(python), "-m", "pip", "install", str(artifact), cwd=target)
            run(str(python), "-m", "pip", "check", cwd=target)
            run(str(openshield), "--help", cwd=target)
            run(str(openshield), "--version", cwd=target)
            run(str(openshield), "scan", "--help", cwd=target)
            verification = """
import importlib.resources as resources
import importlib.util
from importlib.metadata import metadata
import contextlib
import io
import json
import pathlib
import sys
from types import SimpleNamespace
from unittest.mock import patch
from azure.core.exceptions import ClientAuthenticationError
from scanner.engine import ScanEngine
from openshield import cli
from openshield.severity import CONTRACT_VERSION

assert 'api' not in sys.modules
assert CONTRACT_VERSION
distribution = metadata('owasp-openshield')
assert distribution['Name'] == 'owasp-openshield'
assert distribution['Requires-Python'].startswith('>=3.11')
requirements = ' '.join(distribution.get_all('Requires-Dist') or []).lower()
assert all(name not in requirements for name in ('flask', 'psycopg', 'alembic', 'gunicorn'))
assert importlib.util.find_spec('api') is None
assert not (pathlib.Path(str(resources.files('scanner'))) / 'worker.py').exists()
assert not (pathlib.Path(str(resources.files('scanner'))) / 'enrichment_worker.py').exists()
rules = pathlib.Path(str(resources.files('scanner.rules')))
manifest = set((rules / 'manifest.txt').read_text().splitlines())
assert manifest and manifest == {p.stem for p in rules.glob('az_*.py')}
engine = ScanEngine('00000000-0000-0000-0000-000000000001')
assert not engine.rule_load_failures
assert len(engine.rules) == len(manifest)
playbooks = resources.files('playbooks.cli')
for rule in engine.rules:
    reference = getattr(rule, 'PLAYBOOK', '')
    assert reference.startswith('playbooks/cli/'), rule.RULE_ID
    assert playbooks.joinpath(pathlib.Path(reference).name).is_file(), reference
assert 'api' not in sys.modules

class OfflineEngine:
    def __init__(self, subscription_id):
        self.client = SimpleNamespace(credential=SimpleNamespace(get_token=lambda *args: object()))
    def run_scan(self):
        return {'scan_id': 'offline', 'subscription_id': '00000000-0000-0000-0000-000000000001',
                'status': 'completed', 'total_findings': 1,
                'findings': [{'rule_id': 'AZ-TEST-001', 'severity': 'HIGH', 'resource_id': 'resource'}],
                'failed_rule_ids': []}

args = ['scan', '--subscription-id', '00000000-0000-0000-0000-000000000001']
with patch('scanner.engine.ScanEngine', OfflineEngine), patch('openshield.cli._preflight', lambda *args: None):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert cli.main(args) == 0
    assert '[HIGH] AZ-TEST-001' in output.getvalue()
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert cli.main(args + ['--format', 'json']) == 0
    assert json.loads(output.getvalue())['total_findings'] == 1
    OfflineEngine.run_scan = lambda self: {'scan_id': 'offline', 'subscription_id': args[2],
        'status': 'completed', 'total_findings': 0, 'findings': [], 'failed_rule_ids': ['AZ-TEST-002']}
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert cli.main(args + ['--format', 'json']) == 2
    assert json.loads(output.getvalue())['failed_rule_ids'] == ['AZ-TEST-002']

class AuthFailure(OfflineEngine):
    def __init__(self, subscription_id):
        def fail(*args):
            raise ClientAuthenticationError('offline authentication failure')
        self.client = SimpleNamespace(credential=SimpleNamespace(get_token=fail))
with patch('scanner.engine.ScanEngine', AuthFailure):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert cli.main(args + ['--format', 'json']) == 2
    assert json.loads(output.getvalue())['status'] == 'authentication_failed'
"""
            run(str(python), "-c", verification, cwd=target)
            invalid = subprocess.run(
                [str(openshield), "scan", "--subscription-id", "invalid", "--format", "json"],
                cwd=target,
                capture_output=True,
                text=True,
            )
            assert invalid.returncode == 2 and '"status": "invalid_configuration"' in invalid.stdout
            print(f"Verified {artifact.name}")


if __name__ == "__main__":
    main()
