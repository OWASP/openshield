---
title: "How a finding moves through OpenShield"
description: "Trace the path from Azure configuration metadata through rule execution, persistence and the operator-facing API."
pubDate: 2026-09-06
author: "OpenShield Maintainers"
tags: ["Architecture", "Scanner"]
draft: false
---

OpenShield is easier to evaluate when its boundaries are visible. The core path is deliberately small: collect Azure configuration metadata, run repository rules, store normalized findings and expose those records through authenticated API routes.

![OpenShield scan pipeline](/openshield/diagrams/scan-pipeline.svg)

*The core scan path. Optional integrations sit outside rule execution.*

## Start with Azure metadata

The scanner uses the shared `AzureClient` abstraction rather than creating an SDK client inside every rule. This keeps authentication and Azure API access in one place. The documented baseline is the built-in Reader role, although identity checks can require additional Microsoft Graph permissions.

The scanner assesses configuration metadata. It is not designed to collect workload contents, secrets or customer files.

## Load rules through one engine

Each file under `scanner/rules/` declares a rule identifier, name, severity, category, framework mappings and a `scan()` function. The engine discovers those modules and runs them against the shared client.

That structure gives reviewers a direct path from a finding to the code that produced it. It also keeps extension work local: adding a rule does not require rewriting the engine.

## Persist before presenting

Scan and finding records are stored in PostgreSQL. Async scan state also lives in the database, so an API process restart does not erase the job record.

The Flask API then reads the stored evidence for findings, scores, resources, prioritization, drift and playbook routes. The React dashboard is a consumer of those contracts, not the source of the posture data.

## Keep optional systems explicit

CVE enrichment can query NVD after rule execution. AI providers and Microsoft Sentinel are separate integrations. A core scan does not depend on either one.

This distinction matters for deployment planning. Every external connection adds a trust boundary, an availability dependency and a configuration decision. The [interactive architecture map](/openshield/architecture/) exposes those stages individually.

## Remediation remains an operator decision

Findings can reference remediation playbooks, but OpenShield does not automatically execute them against Azure resources. Operators review the command, scope and validation steps before making a change.

That boundary is intentional. Detection and explanation can be automated safely. Cloud mutation still needs explicit authority and context.
