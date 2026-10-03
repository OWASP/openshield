# Compliance Mapping Pack

OpenShield's compliance reports are versioned technical evidence coverage
against a specific edition of a named framework, produced by an internal
OpenShield mapping pack. They are not a certification, an audit opinion, or a
claim of full framework compliance. See "Security limitations" in
`docs/security-requirements.md` for the project-wide disclaimer this section
implements for compliance reporting specifically.

## Supported framework editions

| Framework key | Framework | Edition currently mapped | Source file |
|---|---|---|---|
| `cis` | CIS Microsoft Azure Foundations Benchmark | 2.0.0 (2023-02) | `compliance/frameworks/cis_azure_benchmark.json` |
| `nist` | NIST Cybersecurity Framework | 1.1 | `compliance/frameworks/nist_csf.json` |
| `iso27001` | ISO/IEC 27001 (Annex A) | 2022 | `compliance/frameworks/iso27001.json` |
| `soc2` | AICPA SOC 2 Type II (Trust Services Criteria) | 2017 | `compliance/frameworks/soc2.json` |
| `ncsc_pqc` | NCSC UK PQC Migration Guidance | 2025 | `compliance/frameworks/ncsc_pqc.json` |
| `enisa_pqc` | ENISA Post-Quantum Cryptography Recommendations | 2021 | `compliance/frameworks/enisa_pqc.json` |

These are the only editions OpenShield currently maps. Newer editions (for
example CIS Azure Benchmark 3.x or NIST CSF 2.0) are not mapped yet — do not
present a report generated against an older edition as coverage of a newer
one. When a newer edition is added, the older mapping pack is normally kept
and explicitly marked `"mapping_pack_status": "legacy"` rather than overwritten,
so a report generated under it stays interpretable.

### ISO/IEC 27001: 2013 is superseded, not retained

The ISO/IEC 27001:2013 pack was replaced in place by the 2022 pack (mapping pack
`2.0.0`) instead of being kept as a `legacy` file. The transition period to the
2022 edition ended on 31 October 2025, so certificates against 2013 are no longer
valid and a 2013 pack would only double the maintenance for a withdrawn standard.
Reports do not lose their meaning: every scan stores the mapping-pack snapshot it
was produced with (`compliance_mapping_snapshot`), so a scan made before this
change keeps reporting against the 2013 controls it was scored with, and only
scans made after it report against the 2022 Annex A. A scan saved before full
snapshots existed has no stored controls, so it is scored against the pack on
disk and its `mapping_provenance` says so rather than claiming a snapshot.

The 2022 pack was derived from the published ISO/IEC 27001:2013 to 2022 control
correspondence. Most rules land in the new `A.8` Technological controls. Rules
about detection, alerting and monitoring coverage map to `A.8.16` (Monitoring
activities), and Azure Policy driven configuration governance for Kubernetes maps
to `A.8.9` (Configuration management), both new in 2022. Every entry stays
`pending_review` until a maintainer reviews it, so none counts towards a score yet.

## The mapping-pack schema

Each framework JSON file in `compliance/frameworks/` carries pack-level
metadata plus per-control evidence metadata:

```json
{
  "framework": "CIS Microsoft Azure Foundations Benchmark",
  "version": "2.0.0",
  "published": "2023-02",
  "mapping_pack_version": "1.0.0",
  "mapping_pack_status": "current",
  "mapping_pack_source": "...",
  "mapping_pack_published": "2026-08-22",
  "controls": {
    "AZ-STOR-001": {
      "control_id": "3.5",
      "control_name": "...",
      "description": "...",
      "mapping_type": "direct",
      "evidence_type": "automated_configuration_scan",
      "primary_source": "CIS Microsoft Azure Foundations Benchmark v2.0.0, control 3.5",
      "rationale": "...",
      "owner": null,
      "review_status": "pending_review",
      "review_date": null
    }
  }
}
```

| Field | Meaning |
|---|---|
| `mapping_pack_version` | Semantic version of OpenShield's mapping pack for this framework file, independent of the framework's own edition/version. |
| `mapping_pack_status` | `"current"` or `"legacy"`. Exactly one mapping pack per framework should be `"current"` at a time. |
| `mapping_pack_source` | Free text describing what the mapping pack was authored against. |
| `mapping_pack_published` | Date this mapping pack revision was published. |
| `mapping_type` | `"direct"` — the rule's PASS/FAIL result is itself the control's evidence. `"supporting"` — the rule provides partial automated evidence toward a broader control that also requires organizational or procedural evidence. `"organizational"` — the control is in scope for the framework but cannot be evaluated by a technical scan at all. `"not_applicable"` — this framework edition does not define a control the rule's subject matter belongs to. |
| `evidence_type` | How the evidence was produced, e.g. `"automated_configuration_scan"`. `"not_applicable"` for `not_applicable`/`organizational` controls. |
| `primary_source` | The specific framework document and control identifier this mapping is authored against. |
| `rationale` | Why this `mapping_type` was chosen, grounded in the actual control text and what the rule technically evaluates. |
| `owner` | The person who has independently reviewed this mapping, or `null` if unreviewed. |
| `review_status` | `"pending_review"` or `"reviewed"`. A control cannot be `"reviewed"` without both `owner` and `review_date` set — CI enforces this. |
| `review_date` | ISO date of the last independent review, or `null` if unreviewed. |

## Scoring: what is excluded from the denominator

Any control whose `review_status` is not exactly `"reviewed"` is returned as
`UNREVIEWED_MAPPING`, regardless of `mapping_type`. It contributes to neither
`passed` nor `failed` and is excluded from `score_percent`'s denominator.
This is an evidence gate, not display-only metadata: an unreviewed `direct`
mapping must not be interpreted as validated direct evidence.

`mapping_type: "not_applicable"` and `mapping_type: "organizational"`
controls are likewise listed but excluded from the denominator once reviewed.
`total_controls` includes every mapping; `in_scope_controls` is the reviewed,
scorable denominator. The response also supplies `reviewed_controls`,
`unreviewed_controls`, `not_applicable`, `organizational`, and
`excluded_controls` so consumers can distinguish coverage from mappings still
awaiting review. When every control is unreviewed, `status` is
`NO_REVIEWED_CONTROLS` and `score_percent` is `null`, not `0`.

## Historical accuracy

`api/models/finding.py::save_scan()` snapshots each framework's pack-level
metadata (`framework`, `version`, `mapping_pack_version`,
`mapping_pack_status`, `mapping_pack_source`, `mapping_pack_published`) into
the `scans.compliance_mapping_snapshot` column at scan-completion time.
`get_compliance_score()` prefers that snapshot over the live file when
reporting on a specific scan, so a report for an old scan continues to show
the controls and mapping-pack identity that were actually in effect when it
ran, even after the mapping pack on disk is later revised. The current
review-status interpretation is then applied to those preserved controls;
snapshots are never rewritten or silently reclassified from the live pack.

## Independent review

`review_status` starts as `"pending_review"` for every mapping in this pack.
None of the mappings shipped in the initial 302 mapping-pack revision have
undergone an independent security/compliance review — see the "Acceptance
criteria" evidence in the PR that introduced this file for the current
review status. A maintainer completing that review should set `owner` and
`review_date` and flip `review_status` to `"reviewed"` per entry; CI rejects
a `"reviewed"` entry missing either field.

## What this does not do

- It does not yet implement full per-resource evaluation tracking. Per-control
  `status` is evaluation-derived: it is the rolled-up status of that rule's
  persisted `rule_evaluations` rows for the most recent completed scan (the
  contract from issue #263). A rule with no evaluation row for the scan — a
  legacy rule not yet migrated to `evaluate()`, or one that was skipped — is
  reported `UNKNOWN`, never a `PASS` inferred from the absence of a finding;
  a rule the engine recorded as failing to complete is forced to `ERROR`.
  `UNKNOWN` and `ERROR` stay in the `score_percent` denominator. What is still
  missing is per-resource granularity within a rule that did run: a `PASS`
  does not yet prove the rule executed successfully against *every* applicable
  resource (a timed-out or permission-denied result on a subset cannot be
  distinguished from a clean pass on all of them). `get_compliance_score()`'s
  `evaluation_basis` field states this limitation on every response.
- It does not replace an auditor, a certification body, or a formal
  assessment. See `docs/security-requirements.md`.
