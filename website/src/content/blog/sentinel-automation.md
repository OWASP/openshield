---
title: "Automating Microsoft Sentinel with OpenShield Findings"
description: "Learn how to feed OpenShield's security posture data directly into Azure's enterprise SIEM for unified visibility."
pubDate: 2026-05-20
author: "OpenShield Engineering"
tags: ["integration"]
draft: false
---

Security posture data is most valuable when it's integrated into your existing SOC workflows. OpenShield's Sentinel connector allows you to ingest findings into Log Analytics with a single command, so misconfiguration data lives next to your alerts instead of in a forgotten JSON file.

## Why Sentinel

A scan report answers "how are we doing right now", but a SOC runs on streams. Pushing findings into Log Analytics means posture data participates in the same KQL queries, dashboards and incident workflows as every other signal your team already trusts. It also gives findings a retention policy and an audit trail for free.

## The pipeline

![Findings flow from an OpenShield scan through ingest.py into the Log Analytics Data Collector API, land in the OpenShieldFindings_CL table and feed Sentinel analytics rules](/openshield/diagrams/sentinel-flow.svg)

*Fig. 1: ingest.py normalises each record and signs every batch with the workspace shared key before posting.*

The ingestion client is `sentinel/ingest.py`. It accepts either a JSON list of findings or an object with a `findings` array, normalises the records, and posts them to the Data Collector API under the `OpenShieldFindings` log type.

## Setup in four commands

Create a workspace and read back its credentials:

```bash
az monitor log-analytics workspace create \
  --resource-group openshield-rg \
  --workspace-name openshield-laws \
  --location uksouth \
  --retention-time 30
```

Export the two variables the client reads:

```bash
export SENTINEL_WORKSPACE_ID="your-workspace-id"
export SENTINEL_SHARED_KEY="your-shared-key"
```

Then push a scan. With no arguments the client defaults to `scanner/output/test_findings.json` and mints a scan ID from the UTC timestamp:

```bash
python3 sentinel/ingest.py scanner/output/test_findings.json scan-001
```

The full walkthrough, including the Sentinel onboarding commands, lives in [docs/sentinel-setup.md](https://github.com/openshield-org/openshield/blob/dev/docs/sentinel-setup.md).

## Verify with KQL

In Log Analytics, run:

```kql
OpenShieldFindings_CL | take 10
```

If rows appear, ingestion is working and every future scan is one command away from the same table.

## Analytics rules that ship with the repo

`sentinel/rules/` contains KQL analytics rules ready to deploy in Sentinel or Defender XDR, one scheduled query each:

| Rule file | Severity | Schedule |
|---|---|---|
| `high_severity_finding.kql` | High | Every 1 hour |
| `misconfiguration_wave.kql` | High | Every 2 hours |
| `persistent_misconfiguration.kql` | Medium | Every 24 hours |
| `new_resource_type_critical.kql` | Critical | Every 1 hour |

Set the alert threshold above zero and you have detection-as-code for posture: the same repository that finds the misconfiguration ships the alert that fires if it lingers.

## What good looks like

A fresh scan lands in the workspace, the analytics rules evaluate on their schedules, and the SOC sees a misconfiguration incident in the same queue as every other alert. No bespoke dashboards, no polling scripts, and nothing about the flow leaves Azure. Questions and improvements are welcome on the [community page](/openshield/community/).
