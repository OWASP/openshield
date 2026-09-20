# OpenShield Maintenance & AI Automation Scripts

This directory contains utility scripts for maintaining the OpenShield platform, with a focus on AI RAG pipeline automation, security auditing, and developer productivity.

## Table of Contents
1. [AI RAG Pipeline Scripts](#1-ai-rag-pipeline-scripts)
   - [import_azure_skills.py](#import_azure_skillspy)
   - [generate_rule_keywords.py](#generate_rule_keywordspy)
   - [audit_ai_grounding.py](#audit_ai_groundingpy)
2. [General Utility Scripts](#2-general-utility-scripts)
   - [generate_demo_jwt.py](#generate_demo_jwtpy)

---

## 1. AI RAG Pipeline Scripts

These scripts manage the "Brain" of OpenShield's AI, ensuring it stays grounded in Azure security and synchronized with our scanner rules.

### `generate_rule_keywords.py`
**Purpose:** Uses an LLM to "read" a Python scanner rule and automatically suggest semantic keywords for the AI mapping registry.

**Why it's used:**
- **Zero-Touch:** It removes the need for humans to manually tag rules.
- **Intelligence:** It extracts the *intent* of a rule (e.g., detecting "ssrf" or "privilege escalation") even if those exact words aren't in the title.

**How to use:**
```bash
# Process a single rule
python3 scripts/generate_rule_keywords.py az_net_007.py

# Process all rules in the scanner/rules folder
python3 scripts/generate_rule_keywords.py all
```
*Note: Requires `AI_API_KEY` and `AI_PROVIDER` environment variables.*

### `audit_ai_grounding.py`
**Purpose:** A validation tool that checks for inconsistencies between the Python scanner rules and the AI mapping registry (`ai/knowledge/rule_mapping.json`).

**Why it's used:**
- **Consistency:** Ensures that every `CATEGORY` defined in our Python rules has a corresponding entry in the AI's knowledge base.
- **Integrity:** Flags "Stale References" (mapping for rules that no longer exist) and "Missing Links" (new rules that the AI doesn't know how to use yet).

**How to use:**
```bash
python3 scripts/audit_ai_grounding.py
```

---

## 2. General Utility Scripts

### `generate_demo_jwt.py`
**Purpose:** Mints a short-lived (default 1 hour) read-only `viewer` JWT signed with `JWT_SECRET`, for calling the API locally or in smoke tests when `OPENSHIELD_AUTH_MODE=shared_secret`. It is not accepted in `oidc` mode and must never be placed in frontend configuration (issue #294).

**How to use:**
```bash
JWT_SECRET=<secret> python3 scripts/generate_demo_jwt.py
```

---

## Best Practices for Future Rules
When you add a new scanner rule to OpenShield:
1. Create the `.py` rule in `scanner/rules/`.
2. Run `python3 scripts/generate_rule_keywords.py <your_rule>.py` to update the AI's "Brain."
3. Run `python3 scripts/audit_ai_grounding.py` to verify that the category alignment is perfect.
4. The AI will now automatically include your new rule in its responses!
