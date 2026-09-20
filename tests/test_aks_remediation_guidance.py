"""Regression coverage for AKS remediation and policy-state guidance."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_az_aks_011_playbook_requires_workload_migration() -> None:
    playbook = (ROOT / "playbooks/cli/review_aks_security.sh").read_text()

    assert "prerequisite only" in playbook
    assert "SecretProviderClass" in playbook
    assert "Remove native Secret volume, projected Secret, env, and envFrom references" in playbook
    assert "Key Vault KMS" in playbook


def test_aks_docs_scope_missing_policy_unknown_state() -> None:
    docs = (ROOT / "docs/aks-security-rules.md").read_text()

    assert "four policy-dependent controls UNKNOWN" in docs
    for rule_id in ("AZ-AKS-007", "AZ-AKS-018", "AZ-AKS-019", "AZ-AKS-021"):
        assert rule_id in docs
    assert "other controls continue to evaluate available ARM and Kubernetes evidence" in docs
