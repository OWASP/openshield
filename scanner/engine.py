"""Scan engine: loads rules dynamically and orchestrates a full subscription scan."""

import importlib.util
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
    ``REMEDIATION``, and ``PLAYBOOK``. A rule that also exposes
    ``evaluate(azure_client, subscription_id)`` is run through evaluate()
    only; its findings come from its FAIL evaluations.
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
            completed_at, total_findings, findings, evaluations, and
            failed_rule_ids (rules whose evaluator raised, returned malformed
            data, or produced only ERROR evaluations; partial ERROR results
            do not mark a rule failed when it also produced usable outcomes).
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

        # A rule that raises or returns malformed data is not silently
        # equivalent to "the rule ran and found nothing" - a caller scoring
        # PASS/FAIL from absence of findings (get_compliance_score()) must be
        # able to tell the two apart, or a crashed rule reads as a clean
        # pass. A rule is listed here when it raised, returned malformed
        # data, or produced only ERROR evaluations. Partial ERROR rows do not
        # fail a rule when it also produced usable outcomes; if every outcome
        # is ERROR, the rule supplied no usable coverage and is failed. This
        # also covers inventory-wide failures, while preserving valid results
        # from other inventories/resources.
        failed_rule_ids: List[str] = []

        for rule in self.rules:
            rule_id = getattr(rule, "RULE_ID", "UNKNOWN")
            if callable(getattr(rule, "evaluate", None)):
                # evaluate() supersedes scan(): its FAIL evaluations carry the
                # findings (collected below), so also calling scan() would only
                # repeat the same Azure list calls and let the two paths drift.
                rule_evaluations, completed = self._run_evaluate(rule, rule_id)
                if not completed or (
                    rule_evaluations and all(e.status == EvaluationStatus.ERROR for e in rule_evaluations)
                ):
                    failed_rule_ids.append(rule_id)
                evaluations.extend(rule_evaluations)
                logger.info("Rule %s produced %d evaluation(s)", rule_id, len(rule_evaluations))
                continue

            try:
                rule_findings = rule.scan(self.client, self.subscription_id)
                if not isinstance(rule_findings, list):
                    logger.warning("Rule %s returned %s instead of list — skipped", rule_id, type(rule_findings))
                    failed_rule_ids.append(rule_id)
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
                failed_rule_ids.append(rule_id)

            evaluations.append(self._legacy_placeholder(rule_id))

        # Every FAIL evaluation contributes its attached finding once per
        # (rule_id, resource_id), so repeated FAILs for one resource never
        # double-count.
        existing_keys = {(f.get("rule_id"), f.get("resource_id")) for f in findings}
        for rule_evaluation in evaluations:
            if rule_evaluation.status != EvaluationStatus.FAIL:
                continue
            if not rule_evaluation.finding:
                # A FAIL without a finding would drop a real violation from
                # the findings list while the coverage row still says FAIL.
                logger.warning(
                    "Rule %s reported FAIL for %s without a finding",
                    rule_evaluation.rule_id,
                    rule_evaluation.resource_id,
                )
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
            "failed_rule_ids": failed_rule_ids,
        }

        logger.info("Scan %s complete — %d total finding(s). Normalising results...", scan_id, len(findings))

        return make_serializable(result)

    def _legacy_placeholder(self, rule_id: str) -> RuleEvaluation:
        """Coverage for a rule that only has scan().

        Such a rule has never stated what it looked at, so its coverage is
        recorded as UNKNOWN rather than inferred as PASS from the absence of
        a finding.
        """
        return RuleEvaluation(
            rule_id=rule_id,
            resource_id=subscription_scope_id(self.subscription_id),
            resource_type="",
            status=EvaluationStatus.UNKNOWN,
            reason_code="LEGACY_RULE_NOT_MIGRATED",
            reason="This rule has not been migrated to the evaluate() coverage contract yet.",
        )

    def _run_evaluate(self, rule: Any, rule_id: str) -> Tuple[List[RuleEvaluation], bool]:
        """Run a rule's evaluate() and report whether it completed.

        A raised exception or a non-list return is recorded as a single ERROR
        at the subscription scope. Items that are not RuleEvaluation objects
        are dropped (they must not reach result serialisation, where they
        would fail the whole scan), the valid evaluations are kept so their
        FAIL findings still surface, and one ERROR naming the malformed
        positions is added so the rule cannot read as clean.
        """
        try:
            rule_evaluations = rule.evaluate(self.client, self.subscription_id)
            if not isinstance(rule_evaluations, list):
                raise TypeError(f"evaluate() must return a list, got {type(rule_evaluations)}")
        except Exception as exc:
            RULE_ERRORS_TOTAL.labels(rule_id=rule_id).inc()
            logger.error("Rule %s evaluate() raised an exception: %s", rule_id, exc, exc_info=True)
            return [self._evaluator_error(rule_id, "EVALUATOR_EXCEPTION", str(exc))], False

        valid = [item for item in rule_evaluations if isinstance(item, RuleEvaluation)]
        malformed = [
            f"#{index} ({type(item).__name__})"
            for index, item in enumerate(rule_evaluations)
            if not isinstance(item, RuleEvaluation)
        ]
        if not malformed:
            return rule_evaluations, True

        RULE_ERRORS_TOTAL.labels(rule_id=rule_id).inc()
        reason = f"evaluate() returned {len(malformed)} item(s) that are not RuleEvaluation: {', '.join(malformed)}"
        logger.error("Rule %s %s", rule_id, reason)
        return valid + [self._evaluator_error(rule_id, "MALFORMED_EVALUATION", reason)], False

    def _evaluator_error(self, rule_id: str, reason_code: str, reason: str) -> RuleEvaluation:
        return RuleEvaluation(
            rule_id=rule_id,
            resource_id=subscription_scope_id(self.subscription_id),
            resource_type="",
            status=EvaluationStatus.ERROR,
            reason_code=reason_code,
            reason=reason,
        )
