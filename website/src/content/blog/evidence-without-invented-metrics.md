---
title: "Project evidence without invented metrics"
description: "How the website derives useful project evidence from source files, Git history, releases and documented boundaries."
pubDate: 2026-09-05
author: "OpenShield Maintainers"
tags: ["Evidence", "Open source"]
draft: false
---

Security projects lose credibility when presentation runs ahead of evidence. A polished number is still misleading if nobody can trace where it came from.

OpenShield now separates repository-derived facts, illustrative interface output and manually recorded service status.

## What the build can prove

The website reads the current checkout during every production build. It counts rule files and remediation playbooks, groups rules by Azure domain, reads tagged and commit-linked versions from `CHANGELOG.md`, and derives contributor activity from Git history.

Those values change when their underlying repository sources change. The deployment workflow also watches those source paths, so updates to rules, playbooks, documentation and the changelog trigger a fresh website build.

## What a configured check does not prove

The repository contains CI, CodeQL, dependency review, DCO and signed-release workflows. Their presence proves that the controls are configured. It does not prove that every current run passes.

The evidence page therefore links directly to each workflow and labels it as configured. Current pass or failure state belongs in the GitHub run history, where the execution record exists.

## Why sample output needs a label

Stable sample findings are useful for explaining a CLI or API response. They are not live customer data and should never be presented as such.

The website labels its terminal score as illustrative output. Repository coverage numbers remain separate from the sample scan fixture.

## Boundaries are evidence too

`ROADMAP.md` explicitly excludes automatic remediation, certification claims, workload-content collection, guaranteed detection and premature multi-cloud parity. Those limits are displayed alongside the roadmap direction.

Publishing a limitation is not a weakness. It tells operators where professional judgment and additional controls are still required.

The complete [project evidence page](/openshield/evidence/) brings these sources together without adding customer logos, adoption counts or testimonials that the repository cannot support.
