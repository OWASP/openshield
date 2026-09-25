// ─────────────────────────────────────────────────────────────────────────────
// OpenShield AI API Service
//
// Backend AI endpoints (all POST, require provider + api_key in body):
//   POST /api/ai/ask        — RAG-grounded question answering
//   POST /api/ai/summary    — RAG-grounded executive summary
//   POST /api/ai/insights   — executive summary + remediation plan
//   POST /api/ai/prioritise — AI-ranked findings by real-world exploitability
//
// Findings are never sent from the browser. The backend reads them from a
// completed scan (scanId, or the latest completed scan when omitted), so an
// answer is always grounded in persisted evidence (#357).
//
// If no provider key is configured all AI functions return null.
// CVE analysis calls the public GET /api/score/cve-summary endpoint.
// ─────────────────────────────────────────────────────────────────────────────

import { getToken } from './api.js';

const API_BASE = import.meta.env.VITE_API_URL
  || (import.meta.env.DEV ? 'http://localhost:5000' : 'https://openshield-api.onrender.com');
const TIMEOUT = 30000;

// ── Provider settings ───────────────────────────────────────────────────────
// The API key is the user's own bring-your-own AI provider credential. It is
// kept in memory only for the life of the page — never written to
// localStorage/sessionStorage, which any script running on the page can read
// (XSS-exfiltrable) and which persists indefinitely. The trade-off is that
// the key does not survive a page reload; provider/model (not secret) still
// persist in localStorage as before.
let apiKeyInMemory = '';

// One-time migration: builds before the in-memory switch (issue #180) stored
// the key at localStorage['ai_api_key']. Purge it on load so existing users
// don't keep a plaintext key sitting in storage indefinitely. Deliberately not
// read into apiKeyInMemory — the whole point is that the secret no longer lives
// in a persistent, XSS-readable store.
localStorage.removeItem('ai_api_key');

export const aiSettings = {
  getProvider: () => localStorage.getItem('ai_provider') || 'anthropic',
  getApiKey:   () => apiKeyInMemory,
  getModel:    () => localStorage.getItem('ai_model')    || '',
  save: ({ provider, apiKey, model }) => {
    if (provider)              localStorage.setItem('ai_provider', provider);
    if (apiKey !== undefined)  apiKeyInMemory = apiKey;
    if (model !== undefined)   localStorage.setItem('ai_model', model || '');
  },
  isConfigured: () => !!apiKeyInMemory,
  clear: () => {
    apiKeyInMemory = '';
    localStorage.removeItem('ai_api_key'); // defence in depth: also drop any legacy stored key
    localStorage.removeItem('ai_provider');
    localStorage.removeItem('ai_model');
  },
};

// ── Core fetch ─────────────────────────────────────────────────────────────

async function aiApiFetch(path, body) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT);
  try {
    const token = getToken();
    const res = await fetch(`${API_BASE}/api${path}`, {
      method:  'POST',
      signal:  ctrl.signal,
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(body),
    });
    clearTimeout(t);
    if (!res.ok) throw new Error(`API ${res.status} ${res.statusText}`);
    return res.json();
  } catch (err) {
    clearTimeout(t);
    throw err;
  }
}

function buildBody(extra = {}) {
  return {
    provider: aiSettings.getProvider(),
    api_key:  aiSettings.getApiKey(),
    model:    aiSettings.getModel() || undefined,
    ...extra,
  };
}

// ── Summary normaliser ─────────────────────────────────────────────────────
function normalizeSummary(result) {
  if (!result?.summary) return null;
  return {
    overview:    result.summary,
    generatedAt: new Date().toISOString(),
    aiGenerated: true,
    provider:    result.provider,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Public AI API
// ─────────────────────────────────────────────────────────────────────────────
export const aiApi = {

  settings: aiSettings,

  // ── Chat / Q&A  POST /api/ai/ask ──────────────────────────────────────────
  chat: async ({ question, scanId } = {}) => {
    if (!aiSettings.isConfigured()) return null;
    const result = await aiApiFetch('/ai/ask', buildBody({ question, scan_id: scanId }));
    return {
      answer:  result.answer  || result,
      sources: result.sources || [],
    };
  },

  getSummary: async ({ scanId } = {}) => {
    if (!aiSettings.isConfigured()) return null;
    try {
      return normalizeSummary(await aiApiFetch('/ai/summary', buildBody({ scan_id: scanId })));
    } catch {
      return null;
    }
  },

  getInsights: async ({ question, scanId } = {}) => {
    if (!aiSettings.isConfigured()) return null;
    try {
      return await aiApiFetch('/ai/insights', buildBody({ question, scan_id: scanId }));
    } catch {
      return null;
    }
  },

  getPrioritisation: async ({ scanId } = {}) => {
    if (!aiSettings.isConfigured()) return null;
    try {
      return await aiApiFetch('/ai/prioritise', buildBody({ scan_id: scanId }));
    } catch {
      return null;
    }
  },

  getCVEAnalysis: async () => {
    try {
      const token = getToken();
      const res = await fetch(`${API_BASE}/api/score/cve-summary`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },
};
