---
title: "Why remediation stays explicit"
description: "Detection can be automated, but changing cloud resources requires authority, context and a deliberate operator decision."
pubDate: 2026-09-04
author: "OpenShield Maintainers"
tags: ["Remediation", "Security design"]
draft: false
---

A security scanner can identify a risky configuration without knowing every operational reason behind it. That gap is why OpenShield provides remediation guidance without automatically changing Azure resources.

## A finding is evidence, not authority

A rule can detect that public access is enabled, a network path is broad or an identity assignment is privileged. It cannot infer every availability requirement, exception approval or migration dependency attached to that resource.

Automatic mutation would turn a detection error into an operational incident. A false positive could interrupt a legitimate workload before a person has reviewed its context.

## Playbooks make the proposed change inspectable

Remediation playbooks live under `playbooks/cli/` and are referenced from rule metadata. This lets an operator inspect the command beside the detection logic and framework mapping.

The playbook is a starting point. Scope, resource identifiers and validation steps still need review for the target environment.

## Separate read permission from write permission

The scanner's documented Azure baseline is read-only. Remediation needs separate operator credentials and explicit authorization. Keeping those permissions apart limits the impact of a compromised scanner process or incorrect rule.

This also makes the trust model easier to audit: detection gathers configuration evidence, while remediation is a distinct administrative action.

## Validate after the change

A remediation workflow should include four visible decisions:

1. Confirm that the finding applies to the intended resource.
2. Review the command and its scope.
3. Apply the change through an authorized operator path.
4. Run the relevant validation or scan again.

OpenShield's roadmap keeps automatic remediation out of scope for this period. That is a safety boundary, not an unfinished button.

Read the [rule book](/openshield/rules/) to inspect current rules and their repository-linked playbooks.
