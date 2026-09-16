"""Static contract tests for the distributed container runtime."""

from pathlib import Path
import re

import yaml


ROOT = Path(__file__).resolve().parents[1]


def _yaml(path: str):
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


def _step(steps, name: str):
    return next(step for step in steps if step.get("name") == name)


def test_docker_image_launches_real_wsgi_application_as_non_root():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    startup = (ROOT / "startup.sh").read_text(encoding="utf-8")
    assert "ENV PORT=8000" in dockerfile
    assert 'CMD ["./startup.sh"]' in dockerfile
    assert re.search(r"(?m)^USER openshield$", dockerfile)
    assert startup.index("alembic upgrade head") < startup.index("api.app:application")
    assert "api.app:app " not in startup


def test_docker_build_context_excludes_alternate_git_history():
    entries = {
        line.strip()
        for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert ".git" in entries
    assert ".gitdata" in entries


def test_compose_is_explicitly_local_only_and_migration_aware():
    compose = _yaml("docker-compose.yml")
    assert "version" not in compose
    services = compose["services"]
    assert set(services) == {"db", "api", "worker", "frontend"}
    assert all(service.get("profiles") == ["local"] for service in services.values())

    assert services["db"]["image"] == "postgres:16-alpine"
    assert services["db"]["ports"] == ["127.0.0.1:5432:5432"]
    assert "$$POSTGRES_USER" in services["db"]["healthcheck"]["test"][1]
    assert "postgres_data:/var/lib/postgresql/data" in services["db"]["volumes"]

    api = services["api"]
    assert "command" not in api  # Inherit the image's migration-aware startup path.
    assert api["environment"]["PORT"] == "8000"
    assert api["environment"]["OPENSHIELD_ENV"] == "development"
    assert api["depends_on"]["db"]["condition"] == "service_healthy"
    health_command = " ".join(api["healthcheck"]["test"])
    assert "/ready" in health_command
    assert "urllib.request" in health_command
    assert "status" in health_command
    assert "curl" not in health_command

    worker = services["worker"]
    assert worker["command"] == ["python", "-m", "scanner.worker"]
    assert worker["depends_on"]["api"]["condition"] == "service_healthy"
    assert worker["environment"]["DATABASE_URL"] == api["environment"]["DATABASE_URL"]
    for name in (
        "AZURE_SUBSCRIPTION_ID",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_TENANT_ID",
    ):
        assert name in worker["environment"]


def test_compose_frontend_uses_supported_node_and_browser_api_url():
    compose = _yaml("docker-compose.yml")
    frontend = compose["services"]["frontend"]
    version_match = re.fullmatch(r"node:(\d+)\.(\d+)\.(\d+)-alpine", frontend["image"])
    assert version_match
    assert tuple(map(int, version_match.groups())) >= (22, 22, 0)
    assert "npm ci" in " ".join(frontend["command"])
    assert frontend["environment"]["VITE_API_URL"] == "http://localhost:8000"
    assert frontend["environment"]["NPM_CONFIG_CACHE"] == "/tmp/.npm"
    assert "VITE_API_BASE_URL" not in frontend["environment"]
    assert "frontend_node_modules:/app/node_modules" in frontend["volumes"]
    assert "frontend_node_modules" in compose["volumes"]


def test_terraform_uses_the_frontend_api_variable_the_client_reads():
    terraform = (ROOT / "infra" / "terraform" / "vercel.tf").read_text(encoding="utf-8")
    assert 'key       = "VITE_API_URL"' in terraform
    assert "VITE_API_BASE_URL" not in terraform


def test_ci_builds_starts_and_scans_one_required_image():
    workflow = _yaml(".github/workflows/ci.yml")
    job = workflow["jobs"]["container-scan"]
    assert job["services"]["postgres"]["image"] == "postgres:16"
    assert job["services"]["postgres"]["ports"] == ["5432/tcp"]
    assert job["env"]["IMAGE_TAG"] == "openshield-ci-scan:${{ github.sha }}"

    steps = job["steps"]
    names = [step.get("name") for step in steps]
    assert "Check for Dockerfile" not in names
    assert names.index("Build image") < names.index("Start image")
    assert names.index("Build image") < names.index("Verify BM25 retrieval in fresh image")
    assert names.index("Verify BM25 retrieval in fresh image") < names.index("Start image")
    assert names.index("Start image") < names.index("Verify readiness and non-root runtime")
    assert names.index("Verify readiness and non-root runtime") < names.index("Run Trivy")

    build = _step(steps, "Build image")["run"]
    rag_verify = _step(steps, "Verify BM25 retrieval in fresh image")["run"]
    start = _step(steps, "Start image")["run"]
    verify = _step(steps, "Verify readiness and non-root runtime")["run"]
    trivy = _step(steps, "Run Trivy")
    assert 'docker build --tag "$IMAGE_TAG"' in build
    assert 'docker run --rm --entrypoint python "$IMAGE_TAG"' in rag_verify
    assert "from ai.retriever import retrieve" in rag_verify
    assert "assert results" in rag_verify
    assert '"$IMAGE_TAG"' in start
    assert "--network host" in start
    assert "127.0.0.1:${POSTGRES_PORT}/ci_db" in start
    assert _step(steps, "Start image")["env"]["POSTGRES_PORT"] == "${{ job.services.postgres.ports[5432] }}"
    assert "OPENSHIELD_ENV=production" in start
    assert "secrets.token_urlsafe(32)" in start
    assert "/ready" in verify
    assert '{"status": "ready"}' in verify
    assert 'docker exec "$CONTAINER_NAME" id -u' in verify
    assert trivy["with"]["image-ref"] == "${{ env.IMAGE_TAG }}"
    assert trivy["with"]["exit-code"] == "1"
    assert "!cancelled()" in trivy["if"]
    assert "steps.build.outcome == 'success'" in trivy["if"]
    assert "dockerfile_check" not in (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")


def test_ci_always_cleans_up_and_final_gate_requires_container_job():
    workflow = _yaml(".github/workflows/ci.yml")
    runtime_steps = workflow["jobs"]["container-scan"]["steps"]
    assert _step(runtime_steps, "Show runtime logs on failure")["if"] == "failure()"
    cleanup = _step(runtime_steps, "Remove runtime smoke container")
    assert cleanup["if"] == "always()"
    assert "docker rm --force" in cleanup["run"]
    names = [step.get("name") for step in runtime_steps]
    assert names.index("Remove runtime smoke container") < names.index("Run Trivy")

    summary_steps = workflow["jobs"]["ci-summary"]["steps"]
    final_gate = _step(summary_steps, "Fail if any required job failed")
    assert "needs.container-scan.result != 'success'" in final_gate["if"]
