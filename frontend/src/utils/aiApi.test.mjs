// Minimal, dependency-free test for aiSettings in aiApi.js (issue #180).
//
// frontend/ has no test runner configured (only eslint + vite). aiApi.js has
// no imports and only one Vite-only construct (import.meta.env), so this
// loads the real source (no duplication of the logic under test), replaces
// that one construct with a plain string, and evaluates it with a stubbed
// localStorage — no new devDependency required.
//
// Run with: node frontend/src/utils/aiApi.test.mjs

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function loadAiApiModule(seed = {}) {
  let source = readFileSync(path.join(__dirname, 'aiApi.js'), 'utf8');

  // Neutralize the one Vite-only construct so this can run under plain Node.
  source = source.replace(
    /import\.meta\.env\.VITE_API_URL\s*\|\|\s*\(import\.meta\.env\.DEV \? '[^']*' : '[^']*'\)/,
    "'http://localhost:5000'",
  );
  assert.ok(!source.includes('import.meta'), 'failed to neutralize import.meta usage — test harness is stale');
  // The bearer token comes from api.js's in-memory store; these tests never send requests.
  source = source.replace("import { getToken } from './api.js';", 'const getToken = () => null;');
  assert.ok(!/^import /m.test(source), 'unexpected import in aiApi.js — test harness is stale');

  // Turn `export const x = ...` into `const x = ...` and return the bindings
  // via a wrapper function, so the real module body runs unmodified.
  source = source.replace(/^export const /gm, 'const ');
  source += '\nreturn { aiSettings, aiApi };';

  // `seed` pre-populates localStorage before the module body runs, so tests can
  // simulate a browser that already has values from a previous app version
  // (e.g. a legacy plaintext ai_api_key that predates the in-memory switch).
  const backingStore = new Map(Object.entries(seed));
  const localStorageStub = {
    getItem: (k) => (backingStore.has(k) ? backingStore.get(k) : null),
    setItem: (k, v) => backingStore.set(k, String(v)),
    removeItem: (k) => backingStore.delete(k),
  };

  const load = new Function('localStorage', 'fetch', 'AbortController', 'setTimeout', 'clearTimeout', source);
  const noopFetch = () => Promise.reject(new Error('fetch should not be called in this test'));
  const mod = load(localStorageStub, noopFetch, AbortController, setTimeout, clearTimeout);
  return { ...mod, backingStore };
}

let failures = 0;
function check(description, fn) {
  try {
    fn();
    console.log(`PASS: ${description}`);
  } catch (err) {
    failures++;
    console.error(`FAIL: ${description}\n  ${err.message}`);
  }
}

// ── Fresh module per check: apiKeyInMemory is module-scoped state ──────────

check('starts unconfigured with no key', () => {
  const { aiSettings } = loadAiApiModule();
  assert.equal(aiSettings.isConfigured(), false);
  assert.equal(aiSettings.getApiKey(), '');
});

check('save() persists the key in memory and isConfigured() reflects it', () => {
  const { aiSettings } = loadAiApiModule();
  aiSettings.save({ provider: 'anthropic', apiKey: 'sk-test-12345' });
  assert.equal(aiSettings.isConfigured(), true);
  assert.equal(aiSettings.getApiKey(), 'sk-test-12345');
});

check('the API key is never written to localStorage under any key', () => {
  const { aiSettings, backingStore } = loadAiApiModule();
  aiSettings.save({ provider: 'groq', apiKey: 'super-secret-key-value', model: 'llama' });
  for (const storedValue of backingStore.values()) {
    assert.ok(
      !String(storedValue).includes('super-secret-key-value'),
      `API key leaked into localStorage: ${JSON.stringify([...backingStore.entries()])}`,
    );
  }
});

check('provider and model (non-secret) do persist in localStorage', () => {
  const { aiSettings, backingStore } = loadAiApiModule();
  aiSettings.save({ provider: 'gemini', apiKey: 'irrelevant', model: 'gemini-pro' });
  assert.equal(backingStore.get('ai_provider'), 'gemini');
  assert.equal(backingStore.get('ai_model'), 'gemini-pro');
});

check('clear() removes the in-memory key and localStorage entries', () => {
  const { aiSettings, backingStore } = loadAiApiModule();
  aiSettings.save({ provider: 'anthropic', apiKey: 'to-be-cleared' });
  assert.equal(aiSettings.isConfigured(), true);
  aiSettings.clear();
  assert.equal(aiSettings.isConfigured(), false);
  assert.equal(aiSettings.getApiKey(), '');
  assert.equal(backingStore.has('ai_provider'), false);
  assert.equal(backingStore.has('ai_model'), false);
});

check('a fresh module load never sees a key from a previous instance (no shared storage)', () => {
  const first = loadAiApiModule();
  first.aiSettings.save({ provider: 'anthropic', apiKey: 'first-instance-key' });

  const second = loadAiApiModule();
  assert.equal(second.aiSettings.isConfigured(), false);
  assert.equal(second.aiSettings.getApiKey(), '');
});

check('loading the module purges a legacy plaintext ai_api_key left by an older version', () => {
  // Users who ran a build before the in-memory switch (issue #180) still have
  // their key sitting in localStorage. The module must delete it on load, or
  // the very leak the fix was meant to close persists indefinitely for them.
  const { backingStore } = loadAiApiModule({ ai_api_key: 'legacy-plaintext-key' });
  assert.equal(backingStore.has('ai_api_key'), false);
  assert.ok(
    ![...backingStore.values()].some((v) => String(v).includes('legacy-plaintext-key')),
    'legacy key still present in localStorage after module load',
  );
});

check('the migration does not resurrect the legacy key into the in-memory field', () => {
  // Purging the stored key must not silently load it into memory either — a
  // fresh load with a legacy key present should still start unconfigured.
  const { aiSettings } = loadAiApiModule({ ai_api_key: 'legacy-plaintext-key' });
  assert.equal(aiSettings.isConfigured(), false);
  assert.equal(aiSettings.getApiKey(), '');
});

check('clear() also removes any legacy ai_api_key still in storage', () => {
  const { aiSettings, backingStore } = loadAiApiModule({ ai_api_key: 'legacy-plaintext-key' });
  aiSettings.clear();
  assert.equal(backingStore.has('ai_api_key'), false);
});

if (failures > 0) {
  console.error(`\n${failures} test(s) failed`);
  process.exit(1);
}
console.log('\nAll aiSettings tests passed');
