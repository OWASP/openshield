"""Feature-stack PRs must receive the same read-only checks as dev PRs."""

from fnmatch import fnmatchcase
from pathlib import Path

import pytest
import yaml


@pytest.mark.parametrize("workflow", ["ci", "codeql", "dco", "dependency-review", "website"])
@pytest.mark.parametrize(
    "base",
    [
        "feat/311-finding-lifecycle",
        "feat/331-evidence-graph-foundation",
        "feat/332-evidence-graph-node-edge-population",
    ],
)
def test_feature_stack_receives_required_checks(workflow, base):
    config = yaml.load(Path(f".github/workflows/{workflow}.yml").read_text(), Loader=yaml.BaseLoader)
    patterns = config["on"]["pull_request"]["branches"]
    assert any(fnmatchcase(base, pattern) for pattern in patterns)


@pytest.mark.parametrize("workflow", ["ci", "codeql", "website"])
def test_feature_stack_does_not_expand_push_or_deployment_triggers(workflow):
    config = yaml.load(Path(f".github/workflows/{workflow}.yml").read_text(), Loader=yaml.BaseLoader)
    assert set(config["on"]["push"]["branches"]) <= {"dev", "main"}
