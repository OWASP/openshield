from pathlib import Path

import pytest
import yaml

from scripts import render_deploy_preflight

ROOT = Path(__file__).resolve().parents[1]


def valid_environment(target="staging", smoke=False):
    branch = "dev" if target == "staging" else "main"
    env = {
        "DEPLOY_ENVIRONMENT": target,
        "GITHUB_REF_NAME": branch,
        "GITHUB_SHA": "abc123",
        "RENDER_API_KEY": "key",
        "RENDER_STAGING_SERVICE_ID": "srv-staging-api",
        "RENDER_STAGING_WORKER_SERVICE_ID": "srv-staging-worker",
        "RENDER_PRODUCTION_SERVICE_ID": "srv-production-api",
        "RENDER_PRODUCTION_WORKER_SERVICE_ID": "srv-production-worker",
        "STAGING_API_URL": "https://staging.example.test",
        "PRODUCTION_API_URL": "https://production.example.test",
        "RUN_SMOKE_TESTS": str(smoke).lower(),
    }
    if smoke:
        env.update({name: "configured" for name in render_deploy_preflight.SMOKE_SECRETS})
    return env


@pytest.mark.parametrize("target,branch", [("staging", "dev"), ("production", "main")])
def test_environment_maps_to_expected_branch_and_services(target, branch):
    env = valid_environment(target)
    env["GITHUB_REF_NAME"] = branch
    config = render_deploy_preflight.validate(env)
    assert target in config.api_service_id
    assert target in config.worker_service_id
    assert target in config.api_url
    assert config.commit_sha == "abc123"


@pytest.mark.parametrize("target,branch", [("staging", "main"), ("production", "dev"), ("production", "feature")])
def test_invalid_branch_environment_fails_before_deployment(target, branch, monkeypatch):
    env = valid_environment(target)
    env["GITHUB_REF_NAME"] = branch
    post_calls = []
    monkeypatch.setattr("scripts.render_deploy._open", lambda request: post_calls.append(request))
    with pytest.raises(SystemExit):
        render_deploy_preflight.validate(env)
    assert post_calls == []


@pytest.mark.parametrize(
    "missing",
    [
        "RENDER_API_KEY",
        "RENDER_STAGING_SERVICE_ID",
        "RENDER_STAGING_WORKER_SERVICE_ID",
        "STAGING_API_URL",
        "GITHUB_SHA",
    ],
)
def test_missing_deployment_value_fails_before_post(missing, monkeypatch):
    env = valid_environment()
    env[missing] = ""
    post_calls = []
    monkeypatch.setattr("scripts.render_deploy._open", lambda request: post_calls.append(request))
    with pytest.raises(SystemExit):
        render_deploy_preflight.validate(env)
    assert post_calls == []


def test_smoke_secrets_are_optional_when_smoke_tests_disabled():
    render_deploy_preflight.validate(valid_environment(smoke=False))


@pytest.mark.parametrize("secret", render_deploy_preflight.SMOKE_SECRETS)
def test_each_smoke_secret_is_required_when_enabled(secret):
    env = valid_environment(smoke=True)
    env[secret] = ""
    with pytest.raises(SystemExit):
        render_deploy_preflight.validate(env)


def test_workflow_orders_api_migration_before_worker_deploy_and_gates():
    workflow = yaml.safe_load((ROOT / ".github/workflows/deploy.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["deploy"]
    steps = job["steps"]
    names = [step["name"] for step in steps]
    assert job["environment"] == "${{ inputs.environment }}"
    assert names.index("Validate deployment preflight") < names.index("Create API deployment")
    assert names.index("Create API deployment") < names.index("Wait for API deployment")
    assert names.index("Wait for API deployment") < names.index("Create worker deployment")
    assert names.index("Create worker deployment") < names.index("Wait for worker deployment")
    assert names.index("Require both deployments to be live") < names.index("Health gate check")
    assert names.index("Health gate check") < names.index("Run smoke tests against live deployment")

    by_name = {step["name"]: step for step in steps}
    api_create = by_name["Create API deployment"]
    worker_create = by_name["Create worker deployment"]
    assert api_create["env"]["GITHUB_SHA"] == worker_create["env"]["GITHUB_SHA"] == "${{ github.sha }}"
    assert "continue-on-error" not in by_name["Wait for API deployment"]
    assert by_name["Wait for API deployment"]["env"]["RENDER_DEPLOY_ID"] == "${{ steps.create_api.outputs.deploy_id }}"
    assert by_name["Wait for worker deployment"]["env"]["RENDER_DEPLOY_ID"] == (
        "${{ steps.create_worker.outputs.deploy_id }}"
    )
    assert by_name["Run smoke tests against live deployment"]["if"] == "inputs.run_smoke_tests"


def test_render_blueprint_disables_auto_deploy_and_preserves_service_layout():
    blueprint = yaml.safe_load((ROOT / "render.yaml").read_text(encoding="utf-8"))
    services = blueprint["services"]
    assert len(services) == 4
    assert all(service["autoDeployTrigger"] == "off" for service in services)
    staging = [service for service in services if service["name"].endswith("-staging")]
    production = [service for service in services if not service["name"].endswith("-staging")]
    assert {service["branch"] for service in staging} == {"dev"}
    assert {service["branch"] for service in production} == {"main"}
    assert {service["type"] for service in services} == {"web", "worker"}
    assert all(service["startCommand"] == "./startup.sh" for service in services if service["type"] == "web")
    assert all(
        service["startCommand"] == "python -m scanner.worker" for service in services if service["type"] == "worker"
    )
    for service in services:
        env_vars = {entry["key"]: entry for entry in service["envVars"]}
        if service["type"] == "web":
            assert env_vars["ALLOWED_ORIGINS"]["sync"] is False
        else:
            assert "ALLOWED_ORIGINS" not in env_vars
