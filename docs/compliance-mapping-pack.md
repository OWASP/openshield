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
| `iso27001` | ISO/IEC 27001 | 2013 | `compliance/frameworks/iso27001.json` |
| `soc2` | AICPA SOC 2 Type II (Trust Services Criteria) | 2017 | `compliance/frameworks/soc2.json` |
| `ncsc_pqc` | NCSC UK PQC Migration Guidance | 2025 | `compliance/frameworks/ncsc_pqc.json` |
| `enisa_pqc` | ENISA Post-Quantum Cryptography Recommendations | 2021 | `compliance/frameworks/enisa_pqc.json` |

These are the only editions OpenShield currently maps. Newer editions (for
example CIS Azure Benchmark 3.x, NIST CSF 2.0, or ISO/IEC 27001:2022) are not
mapped yet — do not present a report generated against an older edition as
coverage of a newer one. When a newer edition is added, the older mapping
pack must be kept and explicitly marked `"mapping_pack_status": "legacy"`
rather than overwritten, so a report generated under it stays interpretable.

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

`mapping_type: "not_applicable"` and `mapping_type: "organizational"`
controls are listed in a compliance report but excluded from
`score_percent`'s denominator — they contribute to neither `passed` nor
`failed`. A report's `total_controls` count includes them;
`in_scope_controls` is the denominator actually used for the score.

## Historical accuracy

`api/models/finding.py::save_scan()` snapshots each framework's pack-level
metadata (`framework`, `version`, `mapping_pack_version`,
`mapping_pack_status`, `mapping_pack_source`, `mapping_pack_published`) into
the `scans.compliance_mapping_snapshot` column at scan-completion time.
`get_compliance_score()` prefers that snapshot over the live file when
reporting on a specific scan, so a report for an old scan continues to show
the mapping-pack identity that was actually in effect when it ran, even
after the mapping pack on disk is later revised.

## Independent review

`review_status` starts as `"pending_review"` for every mapping in this pack.
None of the mappings shipped in the initial 302 mapping-pack revision have
undergone an independent security/compliance review — see the "Acceptance
criteria" evidence in the PR that introduced this file for the current
review status. A maintainer completing that review should set `owner` and
`review_date` and flip `review_status` to `"reviewed"` per entry; CI rejects
a `"reviewed"` entry missing either field.

## What this does not do

- It does not implement per-resource evaluation tracking. `PASS` currently
  means "no findings for this rule in the most recent completed scan," not
  "this rule was confirmed to run successfully against every applicable
  resource." An errored or skipped rule cannot yet be distinguished from a
  clean pass — that requires the persisted rule-evaluation contract tracked
  in issue #263. `get_compliance_score()`'s `evaluation_basis` field states
  this limitation on every response.
- It does not replace an auditor, a certification body, or a formal
  assessment. See `docs/security-requirements.md`.
