# CSPM AI Agent: In-Tenant RAG + Guardrails — Design Spec

**Date:** 2026-11-06
**Status:** Draft for review
**Builds on:** PR #397 (`feat/355-cspm-ai-agent`), its audit, and the `api/services/ai_provider.py` abstraction
**Depends on:** #326 (finding lifecycle schema) for the live-finding tools

## 1. Purpose

A conversational CSPM assistant for Azure that a user can talk to in natural
language to find and understand their security gaps ("what are my critical
findings", "am I MCSB compliant", "how do I fix finding 1423"). It must give
**trustworthy, grounded** answers, keep **scan data inside the customer's own
cloud boundary**, and be **resistant to being compromised** (prompt injection,
exfiltration, cross-tenant leakage).

## 2. Locked decisions (from brainstorming)

1. **Retrieval is hybrid, with an exact-query backstop.** Everything is
   retrievable for context and explanation (the "RAG over everything" goal),
   but any **quantitative or authoritative** answer (counts, lists, compliance
   pass/fail, "show my criticals") is served by an **exact structured query**,
   never by vector similarity. A security tool must never undercount criticals.
2. **Model runs in-tenant.** Default backend is **Azure OpenAI / Azure AI
   Foundry** running in the customer's own Azure tenant. Scan data never leaves
   the Azure boundary the customer already trusts and already exposed to
   OpenShield. No data is sent to OpenAI/Anthropic as companies; no training.
3. **Provider interface is thin and pluggable, but we build only the Azure
   backend now.** The interface allows a future Bedrock/Vertex (for non-Azure
   customers, in *their* cloud) or a self-hosted local model (air-gap/defense)
   as a config swap, with no code rewrite. We do **not** build or operate a
   local model now (YAGNI: Azure customers already trust Azure, so a local LLM
   is pure operational headache for zero added trust).
4. **Guardrails are mandatory and backend-independent.** They sit below the
   model and hold regardless of which provider runs.
5. **Native tool-use API, not hand-rolled JSON parsing.** Replace #397's
   "ask the model to emit JSON and parse it" loop (the audit's H1 crash source)
   with the provider's structured tool-calling interface.

## 3. Architecture

```
User (chat / CLI / MCP)
        |
   [ API route: POST /api/agent/query ]   <- authN, tenant+role from session, rate limit
        |
   [ Agent orchestrator (tool-use loop) ] <- native tool-use via provider adapter
        |                         |
philosophy: model never sees      |
raw infra data as instructions    |
        |                         |
   [ Guardrail layer ] ---- enforced below the model ----+
        |                         |                        |
 [ Structured tools ]      [ Knowledge retrieval ]   [ Provider adapter ]
 (exact SQL, tenant-scoped) (pgvector, tenant-scoped) (Azure OpenAI in-tenant)
        |                         |
   Postgres (findings,       Postgres + pgvector
   compliance, scans)        (playbooks, framework text,
                             rule docs, finding narratives)
```

### 3.1 Components (each has one clear job)

- **API route** (`api/routes/agent.py`, exists): authenticates, derives
  `tenant_id` and `user_role` from the session (never from the body), checks
  the subscription allowlist, rate-limits, and calls the orchestrator. Returns
  a single JSON answer. Already close; keep and harden.
- **Agent orchestrator** (`api/agent/agent.py`, rewrite the loop): runs the
  provider's native tool-use loop, dispatches tool calls, enforces iteration
  caps and dedupe, and assembles the final grounded answer with citations.
- **Provider adapter** (`api/services/ai_provider.py`, extend): one interface,
  `complete_with_tools(messages, tools) -> (text | tool_calls)`. First
  implementation: Azure OpenAI (in-tenant). Interface shaped so Bedrock/Vertex/
  local can be added later without touching the orchestrator.
- **Structured tools** (`api/agent/tools.py`, repoint after #326): exact,
  tenant-scoped SQL for the authoritative facts. `scan_subscription` (write,
  RBAC-gated, uses the real scan-admission path), `get_findings`,
  `get_compliance_posture`, `explain_finding`, `suggest_remediation`,
  `get_attack_paths` (stub until #352-354).
- **Knowledge retrieval** (new, `api/agent/retrieval.py`): embeds and
  vector-searches unstructured knowledge and finding narratives via **pgvector
  in the existing Postgres** (no new infra). Returns ranked chunks with source
  metadata for citation. Tenant-scoped at the SQL level.
- **Guardrail layer** (new, `api/agent/guardrails.py` + enforced in the tools):
  see section 5.

### 3.2 Data flow (a question)

1. Route authenticates; binds `tenant_id`, `user_role`, `subscription_id`.
2. Orchestrator sends the question + tool schemas to the in-tenant model.
3. Model asks for tools. Each call is dispatched with tenant/subscription
   injected server-side; retrieved content is wrapped as untrusted data.
4. Authoritative numbers come from structured tools; explanation/context comes
   from knowledge retrieval. Both are tenant-scoped in SQL.
5. Orchestrator returns a grounded answer with citations and a validated
   confidence; every return path is sanitized.

## 4. Retrieval design (hybrid + exact backstop)

- **Structured layer (source of truth):** findings, compliance, scans. Exact
  SQL, tenant-scoped. Any count/list/compliance verdict comes only from here.
- **Vector layer (context + explanation):** `pgvector` tables holding embedded
  (a) remediation playbooks (`playbooks/cli/*.sh` + rule remediation text),
  (b) compliance control text and mappings (MCSB/CIS/ISO), (c) rule
  descriptions/metadata, (d) per-finding narrative text (description +
  remediation + resource), each row carrying `tenant_id` and source metadata.
- **The backstop rule (prompt + orchestration):** the model is instructed, and
  the orchestrator enforces, that quantitative claims must cite a structured
  tool result. If the model answers a "how many / list" question without a
  structured tool call, the orchestrator forces the exact tool before
  answering.
- **Embeddings** generated by the in-tenant model's embedding endpoint (Azure
  OpenAI embeddings), so even embedding stays in-tenant.

## 5. Guardrail layer (anti-compromise)

Threat model: the agent is wired to live infra data + an LLM, so finding text,
resource names, and remediation notes are attacker-influenceable.

- **Untrusted-data handling:** all retrieved/scanned strings are wrapped and
  labelled as data, never instructions. Retrieved content may never change tool
  selection, tenant scope, or role. System prompt is immutable and separated
  from data.
- **Tenant/subscription from session only:** injected server-side into every
  tool and every retrieval query; never read from model output. The tenant
  filter is enforced in SQL below the LLM, so a fully hijacked model still
  cannot read another tenant.
- **No outbound channel:** the agent can call read tools and answer the user,
  nothing else. No web fetch, no email, no arbitrary HTTP. This removes the
  exfiltration leg of the "lethal trifecta," so a successful injection has
  nowhere to send data.
- **RBAC on writes:** read tools open to `viewer`; state-changing tools
  (`scan_subscription`) gated to `operator`/`admin`, enforced server-side in
  both the API and the MCP paths.
- **Output safety:** `clean_text` applied to every return path (the audit found
  two that skip it); `confidence` validated against `{HIGH, LOW}`; model output
  validated as the expected shape before use (kills the audit's H1 crashes).
- **Rate limiting + full audit log:** every question, tool call (with args),
  and answer is logged per tenant/user for abuse detection and forensics.
- **Fail closed, never false-clear:** a tool that cannot read its data returns
  an explicit error the model must surface, never a zeroed "all clear" (fixes
  the audit's C1).

## 6. Fixing the audit findings as part of this work

- **C1 (false all-clear / schema):** repoint finding/compliance tools at #326's
  real tables once it merges; add a Postgres-backed test proving a seeded
  finding is returned; make failures explicit, not zeroed.
- **C2 (MCP bypass):** route MCP through the API with a token, or mark MCP
  single-tenant/local and drop the tenant-isolation claim. RBAC on the MCP
  `scan_subscription` path either way.
- **C3 (scan admission):** `scan_subscription` uses the existing scan-creation
  path (admission + idempotency + audit), not a raw INSERT.
- **H1 (crashes):** replaced by native tool-use + output validation above.
- **H2 (`mcp/` shadowing):** rename to `openshield_mcp/`.
- **Point 6:** drop unused `framework` param or wire it; add `--tenant-id`;
  register `openshield` as a console script; scope the conftest tenant hook.

## 7. Dependencies and sequencing

1. Land **#326** (finding lifecycle schema). Until then, finding tools stay
   honestly stubbed ("data layer not yet available"), never zeroed.
2. Guardrail layer, native tool-use loop, provider adapter, MCP auth, scan-path
   fix, and point-6 cleanups do **not** depend on #326 and can land first.
3. `get_attack_paths` stays stubbed until #352-354.

## 8. Testing

- Postgres-backed tests for every structured tool (seeded data returned
  correctly; tenant isolation holds; failure surfaces as error, not all-clear).
- Guardrail tests: injected instruction in a resource name is ignored; a
  model-supplied tenant_id is overridden by the session; a write tool is denied
  for `viewer`; malformed model output degrades gracefully (no 500).
- Retrieval tests: citations point to real sources; quantitative questions
  force a structured tool call.
- Provider adapter tested against a faked Azure OpenAI tool-use response.

## 9. Out of scope (YAGNI, for now)

- Self-hosted/local model backend (interface allows it; not built).
- Bedrock/Vertex backends (added only when non-Azure customers exist).
- Fine-tuned on-prem model (separate future track).
- Streaming responses, multi-turn memory beyond a single question.

## 10. Open questions

- Exact compliance source: `compliance_scores` exists on neither dev nor #326.
  Decide whether compliance comes from the scoring service, a new table, or is
  marked "not available yet" until a compliance-storage PR lands.
- Whether the MCP server is kept (routed through the API) or deferred until the
  HTTP agent is solid.
