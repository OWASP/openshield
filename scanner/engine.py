"""Scan engine: loads rules dynamically and orchestrates a full subscription scan."""

import importlib.util
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from api.observability import RULE_ERRORS_TOTAL
from openshield.severity import CONTRACT_VERSION, SeverityContractError, normalize_severity, score_findings
from scanner.azure_client import AzureClient
from scanner.evaluation import EvaluationStatus, RuleEvaluation, subscription_scope_id

logger = logging.getLogger(__name__)

RULES_DIR = Path(__file__).parent / "rules"


def make_serializable(data: Any) -> Any:
    """Recursively convert non-serializable objects (datetime, etc) to strings."""
    if data is None:
        return None
    if isinstance(data, (str, int, float, bool)):
        return data
    if isinstance(data, dict):
        return {str(k): make_serializable(v) for k, v in data.items()}
    if isinstance(data, (list, tuple, set)):
        return [make_serializable(i) for i in data]
    if isinstance(data, datetime):
        return data.isoformat()

    # Handle Azure SDK models and other objects
    if hasattr(data, "as_dict") and callable(data.as_dict):
        return make_serializable(data.as_dict())

    # Fallback to string representation for unknown objects
    try:
        # Check if it has a __dict__ but avoid infinite recursion for complex types
        if hasattr(data, "__dict__") and not str(type(data)).startswith("<class 'azure."):
            return make_serializable(data.__dict__)
    except Exception:
        pass

    return str(data)


class ScanEngine:
    """Orchestrates Azure CSPM scans against a target subscription.

    Rules are loaded dynamically at initialisation time from ``scanner/rules/``.
    Each rule module must expose a ``scan(azure_client, subscription_id)``
    function and the module-level constants ``RULE_ID``, ``RULE_NAME``,
    ``SEVERITY``, ``CATEGORY``, ``FRAMEWORKS``, ``DESCRIPTION``,
    ``REMEDIATION``, and ``PLAYBOOK``.
    """

    def __init__(self, subscription_id: str) -> None:
        self.subscription_id = subscription_id
        self.client = AzureClient(subscription_id)
        self.rules: List[Any] = []
        self.load_rules()

    # ------------------------------------------------------------------ #
    # Rule loading                                                          #
    # ------------------------------------------------------------------ #

    def load_rules(self) -> None:
        """Dynamically import every *.py file in scanner/rules/ as a rule module."""
        # Keep runtime discovery identical to CI validation and documentation
        # counts. A misnamed scratch module must never execute against a real
        # subscription without first passing the rule checks.
        for rule_path in sorted(RULES_DIR.glob("az_*.py")):
            try:
                spec = importlib.util.spec_from_file_location(rule_path.stem, rule_path)
                module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
                spec.loader.exec_module(module)  # type: ignore[union-attr]
                rule_id = getattr(module, "RULE_ID", None)
                if callable(getattr(module, "scan", None)) and isinstance(rule_id, str) and rule_id:
                    declared_severity = getattr(module, "SEVERITY", None)
                    if normalize_severity(declared_severity) != declared_severity:
                        raise SeverityContractError(f"rule {rule_id} must declare a canonical severity")
                    self.rules.append(module)
                    logger.info("Loaded rule: %s", rule_id)
                else:
                    logger.warning("Rule file %s has no scan() function or RULE_ID — skipped", rule_path.name)
            except SeverityContractError:
                # A rule outside the contract must fail startup rather than be
                # silently skipped and later appear as a clean evaluation.
                logger.exception("Rule %s has an invalid severity", rule_path.name)
                raise
            except Exception as exc:
                logger.error("Failed to load rule %s: %s", rule_path.name, exc)

    # ------------------------------------------------------------------ #
    # Scan execution                                                        #
    # ------------------------------------------------------------------ #

    def run_scan(self, scan_id: Optional[str] = None) -> Dict[str, Any]:
        """Execute all loaded rules and return a normalised scan result.

        Args:
            scan_id: Optional existing UUID. If not provided, a new one is generated.

        Returns:
            dict with keys: scan_id, subscription_id, started_at,
            completed_at, total_findings, findings.
        """
        scan_id = scan_id or str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        findings: List[Dict[str, Any]] = []
        evaluations: List[RuleEvaluation] = []
        detected_at = datetime.now(timezone.utc).isoformat()

        logger.info(
            "Scan %s starting against subscription %s — %d rules loaded",
            scan_id,
            self.subscription_id,
            len(self.rules),
        )

        for rule in self.rules:
            rule_id = getattr(rule, "RULE_ID", "UNKNOWN")
            try:
                rule_findings = rule.scan(self.client, self.subscription_id)
                if not isinstance(rule_findings, list):
                    logger.warning("Rule %s returned %s instead of list — skipped", rule_id, type(rule_findings))
                    continue

                validated_findings = []
                for raw_finding in rule_findings:
                    finding = raw_finding
                    if not isinstance(finding, dict):
                        logger.warning("Rule %s returned a non-object finding — skipped", rule_id)
                        continue
                    finding = dict(finding)
                    finding["severity"] = normalize_severity(finding.get("severity"))
                    finding.setdefault("detected_at", detected_at)
                    finding.setdefault("scan_id", scan_id)
                    validated_findings.append(finding)
                findings.extend(validated_findings)
                logger.info("Rule %s produced %d finding(s)", rule_id, len(validated_findings))
            except SeverityContractError:
                RULE_ERRORS_TOTAL.labels(rule_id=rule_id).inc()
                logger.exception("Rule %s returned an invalid severity", rule_id)
                raise
            except Exception as exc:
                RULE_ERRORS_TOTAL.labels(rule_id=rule_id).inc()
                logger.error("Rule %s raised an exception: %s", rule_id, exc, exc_info=True)

            evaluations.extend(self._evaluate_rule(rule, rule_id))

        # A FAIL evaluation contributes its own finding only if scan() hasn't
        # already reported the same (rule_id, resource_id) violation, so a
        # rule implementing both scan() and evaluate() never double-counts.
        existing_keys = {(f.get("rule_id"), f.get("resource_id")) for f in findings}
        for rule_evaluation in evaluations:
            if rule_evaluation.status != EvaluationStatus.FAIL or not rule_evaluation.finding:
                continue
            key = (rule_evaluation.rule_id, rule_evaluation.resource_id)
            if key in existing_keys:
                continue
            finding = dict(rule_evaluation.finding)
            finding["severity"] = normalize_severity(finding.get("severity"))
            finding.setdefault("detected_at", detected_at)
            finding.setdefault("scan_id", scan_id)
            findings.append(finding)
            existing_keys.add(key)

        completed_at = datetime.now(timezone.utc).isoformat()

        score = score_findings(findings)

        result = {
            "scan_id": scan_id,
            "subscription_id": self.subscription_id,
            "status": "completed",
            "cve_enrichment_status": "PENDING",
            "started_at": started_at,
            "completed_at": completed_at,
            "total_findings": len(findings),
            "score": score,
            "severity_contract_version": CONTRACT_VERSION,
            "findings": findings,
            "evaluations": [e.to_dict() for e in evaluations],
        }

        logger.info("Scan %s complete — %d total finding(s). Normalising results...", scan_id, len(findings))

        return make_serializable(result)

    def _evaluate_rule(self, rule: Any, rule_id: str) -> List[RuleEvaluation]:
        """Return this rule's coverage statements for the current scan.

        A rule that exposes ``evaluate()`` reports its own PASS/FAIL/UNKNOWN
        results. A rule that only has ``scan()`` has never stated what it
        looked at, so its coverage is recorded as UNKNOWN rather than
        inferred as PASS from the absence of a finding.
        """
        evaluate_fn = getattr(rule, "evaluate", None)
        if not callable(evaluate_fn):
            return [
                RuleEvaluation(
                    rule_id=rule_id,
                    resource_id=subscription_scope_id(self.subscription_id),
                    resource_type="",
                    status=EvaluationStatus.UNKNOWN,
                    reason_code="LEGACY_RULE_NOT_MIGRATED",
                    reason="This rule has not been migrated to the evaluate() coverage contract yet.",
                )
            ]

        try:
            rule_evaluations = evaluate_fn(self.client, self.subscription_id)
            if not isinstance(rule_evaluations, list):
                raise TypeError(f"evaluate() must return a list, got {type(rule_evaluations)}")
            return rule_evaluations
        except Exception as exc:
            RULE_ERRORS_TOTAL.labels(rule_id=rule_id).inc()
            logger.error("Rule %s evaluate() raised an exception: %s", rule_id, exc, exc_info=True)
            return [
                RuleEvaluation(
                    rule_id=rule_id,
                    resource_id=subscription_scope_id(self.subscription_id),
                    resource_type="",
                    status=EvaluationStatus.ERROR,
                    reason_code="EVALUATOR_EXCEPTION",
                    reason=str(exc),
                )
            ]
