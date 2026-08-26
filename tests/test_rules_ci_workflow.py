"""Rule regression tests for AZ-CI-001 through AZ-CI-004 CI/CD workflow security rules."""

from unittest.mock import MagicMock


import scanner.rules.az_ci_001 as az_ci_001
import scanner.rules.az_ci_002 as az_ci_002
import scanner.rules.az_ci_003 as az_ci_003
import scanner.rules.az_ci_004 as az_ci_004
from scanner.rules._workflow_common import (
    collect_uses,
    get_dangerous_triggers,
    get_top_level_permissions,
    is_action_pinned,
    is_permissions_broad,
    parse_workflow,
)


# Workflow with OIDC at job level (no top-level permissions block)
JOB_LEVEL_OIDC_WITH_OTHER_CRED = """
name: Job Level OIDC
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - run: echo build
"""

# Workflow with OIDC and migration comment mentioning old credential
OIDC_WITH_MIGRATION_COMMENT = """
name: OIDC with comment
on: [push]
permissions:
  id-token: write
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      # Old workflow used ARM_CLIENT_SECRET, replaced by federated identity
      - uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
"""

# Workflow with per-job explicit permissions, no top-level block
PER_JOB_PERMISSIONS_WORKFLOW = """
name: Per-job permissions
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - run: echo build
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - run: echo test
"""

# Safe pull_request_target that only uses head.sha in a comment step
SAFE_PRT_BASE_CHECKOUT = """
name: Safe PRT base checkout
on:
  pull_request_target:
    types: [opened]
jobs:
  label:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.event.pull_request.base.sha }}
      - name: Post comment
        run: echo "PR SHA is ${{ github.event.pull_request.head.sha }}"
"""

OWNER = "test-org"
REPO = "test-repo"

# ---------------------------------------------------------------------------
# YAML fixtures
# ---------------------------------------------------------------------------

SECURE_WORKFLOW = """
name: Secure CI
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4
      - run: echo hello
"""

INSECURE_LONG_LIVED_CREDS = """
name: Deploy
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        env:
          AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
      - run: az login --service-principal -u $CLIENT_ID -p $AZURE_CLIENT_SECRET
"""

OIDC_WORKFLOW = """
name: OIDC Deploy
on: [push]
permissions:
  id-token: write
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
"""

BROAD_PERMISSIONS_WORKFLOW = """
name: Broad
on: [push]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"""

NO_PERMISSIONS_WORKFLOW = """
name: No Perms
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"""

UNPINNED_ACTIONS_WORKFLOW = """
name: Unpinned
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - uses: actions/cache@v3
"""

PINNED_ACTIONS_WORKFLOW = """
name: Pinned
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: actions/setup-python@0a5c61591373683505ea898e09a3ea4f39ef2b9c
"""

PWN_REQUEST_WORKFLOW = """
name: Pwn Request
on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: ./ci/build.sh
"""

SAFE_PRT_WORKFLOW = """
name: Safe PRT
on:
  pull_request_target:
    types: [opened]
permissions:
  contents: read
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: echo "labelling only, no checkout"
"""

MALFORMED_YAML = "on: [push\njobs: {"


# ---------------------------------------------------------------------------
# Helper: make a mock GitHubClient
# ---------------------------------------------------------------------------


def _make_client(workflows=None, contents=None):
    client = MagicMock()
    if workflows is None:
        client.get_workflows.return_value = [{"path": ".github/workflows/ci.yml"}]
    else:
        client.get_workflows.return_value = workflows
    if contents is None:
        client.get_workflow_content.return_value = SECURE_WORKFLOW
    elif isinstance(contents, dict):
        client.get_workflow_content.side_effect = lambda p: contents.get(p)
    else:
        client.get_workflow_content.return_value = contents
    return client


# ---------------------------------------------------------------------------
# _workflow_common unit tests
# ---------------------------------------------------------------------------


class TestWorkflowCommon:
    def test_parse_workflow_valid(self):
        wf = parse_workflow(SECURE_WORKFLOW)
        assert wf is not None
        assert "jobs" in wf

    def test_parse_workflow_malformed_returns_none(self):
        assert parse_workflow(MALFORMED_YAML) is None

    def test_is_action_pinned_with_sha(self):
        assert is_action_pinned("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")

    def test_is_action_pinned_with_tag_returns_false(self):
        assert not is_action_pinned("actions/checkout@v4")

    def test_is_action_pinned_local_action(self):
        assert is_action_pinned("./local/action")

    def test_is_action_pinned_docker(self):
        assert is_action_pinned("docker://ghcr.io/my/image:latest")

    def test_collect_uses_finds_all_actions(self):
        wf = parse_workflow(UNPINNED_ACTIONS_WORKFLOW)
        uses = collect_uses(wf)
        assert len(uses) == 3

    def test_collect_uses_empty_workflow(self):
        wf = parse_workflow("name: x\non: [push]\njobs: {}")
        assert collect_uses(wf) == []

    def test_get_top_level_permissions_none_when_absent(self):
        wf = parse_workflow(NO_PERMISSIONS_WORKFLOW)
        assert get_top_level_permissions(wf) is None

    def test_get_top_level_permissions_returns_dict(self):
        wf = parse_workflow(SECURE_WORKFLOW)
        perms = get_top_level_permissions(wf)
        assert isinstance(perms, dict)

    def test_is_permissions_broad_write_all(self):
        assert is_permissions_broad({"all": "write-all"})

    def test_is_permissions_broad_none_is_broad(self):
        assert is_permissions_broad(None)

    def test_is_permissions_broad_read_only_is_not_broad(self):
        assert not is_permissions_broad({"contents": "read"})

    def test_get_dangerous_triggers_detects_prt(self):
        wf = parse_workflow(PWN_REQUEST_WORKFLOW)
        triggers = get_dangerous_triggers(wf)
        assert "pull_request_target" in triggers

    def test_get_dangerous_triggers_safe_workflow(self):
        wf = parse_workflow(SECURE_WORKFLOW)
        assert get_dangerous_triggers(wf) == []


# ---------------------------------------------------------------------------
# AZ-CI-001 tests
# ---------------------------------------------------------------------------


class TestAzCi001:
    def test_long_lived_creds_without_oidc_returns_finding(self):
        client = _make_client(contents=INSECURE_LONG_LIVED_CREDS)
        findings = az_ci_001.scan(client, OWNER, REPO)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "AZ-CI-001"
        assert findings[0]["severity"] == "HIGH"

    def test_oidc_workflow_no_finding(self):
        client = _make_client(contents=OIDC_WORKFLOW)
        findings = az_ci_001.scan(client, OWNER, REPO)
        assert findings == []

    def test_oidc_with_arm_access_key_still_fails(self):
        """OIDC present but ARM_ACCESS_KEY also present must still return a finding."""
        oidc_plus_key = OIDC_WORKFLOW + "\n    env:\n      ARM_ACCESS_KEY: ${{ secrets.ARM_ACCESS_KEY }}\n"
        client = _make_client(contents=oidc_plus_key)
        findings = az_ci_001.scan(client, OWNER, REPO)
        assert len(findings) == 1, "OIDC + ARM_ACCESS_KEY must still flag as long-lived credential"
        assert findings[0]["rule_id"] == "AZ-CI-001"

    def test_secure_workflow_no_finding(self):
        client = _make_client(contents=SECURE_WORKFLOW)
        findings = az_ci_001.scan(client, OWNER, REPO)
        assert findings == []

    def test_none_workflows_returns_empty(self):
        client = _make_client(workflows=None)
        client.get_workflows.return_value = None
        findings = az_ci_001.scan(client, OWNER, REPO)
        assert findings == []

    def test_none_content_skipped(self):
        client = _make_client(contents=None)
        client.get_workflow_content.return_value = None
        findings = az_ci_001.scan(client, OWNER, REPO)
        assert findings == []

    def test_finding_metadata_contains_creds(self):
        client = _make_client(contents=INSECURE_LONG_LIVED_CREDS)
        findings = az_ci_001.scan(client, OWNER, REPO)
        assert "long_lived_credentials_found" in findings[0]["metadata"]

    def test_empty_repo_no_workflows(self):
        client = _make_client(workflows=[])
        findings = az_ci_001.scan(client, OWNER, REPO)
        assert findings == []

    # ---------------------------------------------------------------------------
    # AZ-CI-002 tests
    # ---------------------------------------------------------------------------

    def test_job_level_oidc_no_finding(self):
        """Job-level id-token: write with azure/login and no actual secret must pass."""
        client = _make_client(contents=JOB_LEVEL_OIDC_WITH_OTHER_CRED)
        findings = az_ci_001.scan(client, OWNER, REPO)
        assert findings == [], "Job-level OIDC deploy + unrelated tf-state job must not flag"

    def test_migration_comment_no_finding(self):
        """OIDC workflow with migration comment mentioning old credential must not flag."""
        client = _make_client(contents=OIDC_WITH_MIGRATION_COMMENT)
        findings = az_ci_001.scan(client, OWNER, REPO)
        assert findings == [], "Comment-only credential reference must not trigger finding"


class TestAzCi002:
    def test_write_all_returns_finding(self):
        client = _make_client(contents=BROAD_PERMISSIONS_WORKFLOW)
        findings = az_ci_002.scan(client, OWNER, REPO)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "AZ-CI-002"

    def test_no_permissions_block_returns_finding(self):
        client = _make_client(contents=NO_PERMISSIONS_WORKFLOW)
        findings = az_ci_002.scan(client, OWNER, REPO)
        assert len(findings) == 1

    def test_least_privilege_no_finding(self):
        client = _make_client(contents=SECURE_WORKFLOW)
        findings = az_ci_002.scan(client, OWNER, REPO)
        assert findings == []

    def test_none_workflows_returns_empty(self):
        client = _make_client()
        client.get_workflows.return_value = None
        findings = az_ci_002.scan(client, OWNER, REPO)
        assert findings == []

    def test_finding_metadata_contains_permissions(self):
        client = _make_client(contents=BROAD_PERMISSIONS_WORKFLOW)
        findings = az_ci_002.scan(client, OWNER, REPO)
        assert "permissions_declared" in findings[0]["metadata"]

    def test_empty_repo_no_workflows(self):
        client = _make_client(workflows=[])
        findings = az_ci_002.scan(client, OWNER, REPO)
        assert findings == []

    # ---------------------------------------------------------------------------
    # AZ-CI-003 tests
    # ---------------------------------------------------------------------------

    def test_per_job_explicit_permissions_no_finding(self):
        """No top-level permissions but all jobs declare explicit permissions must not flag."""
        client = _make_client(contents=PER_JOB_PERMISSIONS_WORKFLOW)
        findings = az_ci_002.scan(client, OWNER, REPO)
        assert findings == [], "Per-job least privilege must not be flagged as broad"


class TestAzCi003:
    def test_unpinned_actions_returns_finding(self):
        client = _make_client(contents=UNPINNED_ACTIONS_WORKFLOW)
        findings = az_ci_003.scan(client, OWNER, REPO)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "AZ-CI-003"

    def test_pinned_actions_no_finding(self):
        client = _make_client(contents=PINNED_ACTIONS_WORKFLOW)
        findings = az_ci_003.scan(client, OWNER, REPO)
        assert findings == []

    def test_secure_workflow_no_finding(self):
        client = _make_client(contents=SECURE_WORKFLOW)
        findings = az_ci_003.scan(client, OWNER, REPO)
        assert findings == []

    def test_none_workflows_returns_empty(self):
        client = _make_client()
        client.get_workflows.return_value = None
        findings = az_ci_003.scan(client, OWNER, REPO)
        assert findings == []

    def test_unpinned_metadata_lists_actions(self):
        client = _make_client(contents=UNPINNED_ACTIONS_WORKFLOW)
        findings = az_ci_003.scan(client, OWNER, REPO)
        unpinned = findings[0]["metadata"]["unpinned_actions"]
        assert len(unpinned) == 3
        assert all("@v" in u for u in unpinned)

    def test_malformed_yaml_skipped(self):
        client = _make_client(contents=MALFORMED_YAML)
        findings = az_ci_003.scan(client, OWNER, REPO)
        assert findings == []

    def test_empty_repo_no_workflows(self):
        client = _make_client(workflows=[])
        findings = az_ci_003.scan(client, OWNER, REPO)
        assert findings == []


# ---------------------------------------------------------------------------
# AZ-CI-004 tests
# ---------------------------------------------------------------------------


class TestAzCi004:
    def test_pwn_request_pattern_returns_finding(self):
        client = _make_client(contents=PWN_REQUEST_WORKFLOW)
        findings = az_ci_004.scan(client, OWNER, REPO)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "AZ-CI-004"

    def test_safe_prt_without_checkout_no_finding(self):
        client = _make_client(contents=SAFE_PRT_WORKFLOW)
        findings = az_ci_004.scan(client, OWNER, REPO)
        assert findings == []

    def test_secure_workflow_no_finding(self):
        client = _make_client(contents=SECURE_WORKFLOW)
        findings = az_ci_004.scan(client, OWNER, REPO)
        assert findings == []

    def test_none_workflows_returns_empty(self):
        client = _make_client()
        client.get_workflows.return_value = None
        findings = az_ci_004.scan(client, OWNER, REPO)
        assert findings == []

    def test_finding_metadata_contains_triggers(self):
        client = _make_client(contents=PWN_REQUEST_WORKFLOW)
        findings = az_ci_004.scan(client, OWNER, REPO)
        assert "dangerous_triggers" in findings[0]["metadata"]
        assert "pull_request_target" in findings[0]["metadata"]["dangerous_triggers"]

    def test_malformed_yaml_skipped(self):
        client = _make_client(contents=MALFORMED_YAML)
        findings = az_ci_004.scan(client, OWNER, REPO)
        assert findings == []

    def test_empty_repo_no_workflows(self):
        client = _make_client(workflows=[])
        findings = az_ci_004.scan(client, OWNER, REPO)
        assert findings == []

    # ---------------------------------------------------------------------------
    # GitHubClient unit tests
    # ---------------------------------------------------------------------------

    def test_prt_base_checkout_with_head_sha_in_comment_no_finding(self):
        """pull_request_target checking out base ref (safe) must not flag even if
        head.sha appears in a run step for display purposes."""
        client = _make_client(contents=SAFE_PRT_BASE_CHECKOUT)
        findings = az_ci_004.scan(client, OWNER, REPO)
        assert findings == [], "Base-ref checkout with head.sha in run step must not flag"


class TestGitHubClient:
    def test_init_sets_owner_repo(self):
        from scanner.github_client import GitHubClient

        client = GitHubClient("my-org", "my-repo", token="test-token")
        assert client.owner == "my-org"
        assert client.repo == "my-repo"

    def test_no_token_returns_none_from_get_token(self):
        import importlib
        import os
        from unittest.mock import patch

        with patch.dict(os.environ, {}, clear=True):
            import scanner.github_client as gh_mod

            importlib.reload(gh_mod)
            token = gh_mod._get_token()
            assert token is None

    def test_get_workflows_returns_none_on_api_failure(self):
        from scanner.github_client import GitHubClient
        from unittest.mock import patch

        client = GitHubClient("org", "repo", token="tok")
        with patch.object(client, "_get", return_value=None):
            result = client.get_workflows()
        assert result is None

    def test_get_workflow_content_returns_none_on_failure(self):
        from scanner.github_client import GitHubClient
        from unittest.mock import patch

        client = GitHubClient("org", "repo", token="tok")
        with patch.object(client, "_get", return_value=None):
            result = client.get_workflow_content(".github/workflows/ci.yml")
        assert result is None
