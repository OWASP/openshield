// Dependency-free request lifecycle tests for api.js.
// Run with: node frontend/src/utils/api.test.mjs

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function loadApiModule({ fetchImpl, timers, token = null } = {}) {
  let source = readFileSync(path.join(__dirname, 'api.js'), 'utf8');
  source = source.replace(
    "import { normalizeRisk, normalizeSeverity } from './severity.js';",
    'const normalizeRisk = (value) => value; const normalizeSeverity = (value) => value;',
  );
  source = source.replace(
    /import\.meta\.env\.VITE_API_URL\s*\|\|\s*\(import\.meta\.env\.DEV \? '[^']*' : '[^']*'\)/,
    "'http://localhost:5000'",
  );
  assert.ok(!source.includes('import.meta'), 'failed to neutralize import.meta usage — test harness is stale');
  source = source.replace(/^export (const|class|async function) /gm, '$1 ');
  source = source.replace(/^export default api;$/m, '');
  source += `\nreturn {
    api, apiFetch, DEFAULT_REQUEST_TIMEOUT_MS, ApiRequestError,
    ApiTimeoutError, ApiCancellationError, ApiHttpError, ApiNetworkError,
  };`;

  const localStorageStub = {
    getItem: (key) => key === 'jwt_token' ? token : null,
    setItem: () => {},
  };
  const load = new Function(
    'localStorage', 'fetch', 'AbortController', 'setTimeout', 'clearTimeout', source,
  );
  return load(
    localStorageStub,
    fetchImpl || (() => Promise.reject(new Error('unexpected fetch'))),
    AbortController,
    timers?.setTimeout || setTimeout,
    timers?.clearTimeout || clearTimeout,
  );
}

function createTimers() {
  const pending = new Map();
  const delays = [];
  let nextId = 1;
  return {
    pending,
    delays,
    setTimeout(fn, delay) {
      const id = nextId++;
      pending.set(id, fn);
      delays.push(delay);
      return id;
    },
    clearTimeout(id) { pending.delete(id); },
    runNext() {
      const entry = pending.entries().next().value;
      assert.ok(entry, 'expected a pending timeout');
      const [id, fn] = entry;
      pending.delete(id);
      fn();
    },
  };
}

function jsonResponse(body, { ok = true, status = 200, statusText = 'OK' } = {}) {
  return { ok, status, statusText, json: async () => body };
}

function rejectWhenAborted(signal) {
  return new Promise((resolve, reject) => {
    const rejectAbort = () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
    if (signal.aborted) rejectAbort();
    else signal.addEventListener('abort', rejectAbort, { once: true });
  });
}

const tests = [];
function test(description, fn) { tests.push({ description, fn }); }

test('successful requests return JSON and clear the default timeout', async () => {
  const timers = createTimers();
  let requestSignal;
  const { apiFetch, DEFAULT_REQUEST_TIMEOUT_MS } = loadApiModule({
    timers,
    fetchImpl: async (_url, options) => {
      requestSignal = options.signal;
      return jsonResponse({ value: 42 });
    },
  });
  assert.deepEqual(await apiFetch('/score'), { value: 42 });
  assert.equal(timers.delays[0], DEFAULT_REQUEST_TIMEOUT_MS);
  assert.equal(timers.pending.size, 0);
  assert.equal(requestSignal.aborted, false);
});

test('non-2xx responses throw an HTTP error with status details', async () => {
  const timers = createTimers();
  const { apiFetch, ApiHttpError } = loadApiModule({
    timers,
    fetchImpl: async () => jsonResponse(null, { ok: false, status: 503, statusText: 'Unavailable' }),
  });
  await assert.rejects(apiFetch('/score'), (err) => {
    assert.ok(err instanceof ApiHttpError);
    assert.equal(err.code, 'HTTP_ERROR');
    assert.equal(err.status, 503);
    return true;
  });
  assert.equal(timers.pending.size, 0);
});

test('network failures are distinct from HTTP failures', async () => {
  const cause = new TypeError('Failed to fetch');
  const { apiFetch, ApiNetworkError } = loadApiModule({
    fetchImpl: async () => { throw cause; },
  });
  await assert.rejects(apiFetch('/score'), (err) => {
    assert.ok(err instanceof ApiNetworkError);
    assert.equal(err.code, 'NETWORK_ERROR');
    assert.equal(err.cause, cause);
    return true;
  });
});

test('response parsing errors are not mislabeled as network failures', async () => {
  const parseError = new SyntaxError('invalid JSON');
  const { apiFetch, ApiNetworkError } = loadApiModule({
    fetchImpl: async () => ({
      ...jsonResponse(null),
      json: async () => { throw parseError; },
    }),
  });
  await assert.rejects(apiFetch('/score'), (err) => {
    assert.equal(err, parseError);
    assert.equal(err instanceof ApiNetworkError, false);
    return true;
  });
});

test('the timeout aborts fetch and throws a typed timeout error', async () => {
  const timers = createTimers();
  const { apiFetch, ApiTimeoutError } = loadApiModule({
    timers,
    fetchImpl: async (_url, { signal }) => rejectWhenAborted(signal),
  });
  const request = apiFetch('/score', { timeoutMs: 250 });
  timers.runNext();
  await assert.rejects(request, (err) => {
    assert.ok(err instanceof ApiTimeoutError);
    assert.equal(err.code, 'TIMEOUT');
    assert.equal(err.timeoutMs, 250);
    return true;
  });
  assert.equal(timers.pending.size, 0);
});

test('caller cancellation is forwarded without being reported as a timeout', async () => {
  const timers = createTimers();
  const caller = new AbortController();
  let internalSignal;
  const { apiFetch, ApiCancellationError } = loadApiModule({
    timers,
    fetchImpl: async (_url, { signal }) => {
      internalSignal = signal;
      return rejectWhenAborted(signal);
    },
  });
  const request = apiFetch('/score', { signal: caller.signal });
  assert.notEqual(internalSignal, caller.signal);
  caller.abort();
  await assert.rejects(request, (err) => {
    assert.ok(err instanceof ApiCancellationError);
    assert.equal(err.code, 'CANCELLED');
    return true;
  });
  assert.equal(internalSignal.aborted, true);
  assert.equal(timers.pending.size, 0);
});

test('an already-aborted caller signal cancels before fetch can proceed', async () => {
  const caller = new AbortController();
  caller.abort();
  const { apiFetch, ApiCancellationError } = loadApiModule({
    fetchImpl: async (_url, { signal }) => rejectWhenAborted(signal),
  });
  await assert.rejects(apiFetch('/score', { signal: caller.signal }), ApiCancellationError);
});

test('public API methods accept operation-specific timeout overrides', async () => {
  const timers = createTimers();
  const { api } = loadApiModule({
    timers,
    fetchImpl: async () => jsonResponse({ score: 90 }),
  });
  assert.deepEqual(await api.getScore({ timeoutMs: 1250 }), { score: 90, max_score: 100 });
  assert.equal(timers.delays[0], 1250);
});

test('a completed request cannot be aborted by a stale timer', async () => {
  const timers = createTimers();
  let requestSignal;
  const { apiFetch } = loadApiModule({
    timers,
    fetchImpl: async (_url, { signal }) => {
      requestSignal = signal;
      return jsonResponse({ done: true });
    },
  });
  await apiFetch('/score', { timeoutMs: 10 });
  assert.equal(timers.pending.size, 0);
  assert.equal(requestSignal.aborted, false);
});

test('a completed request removes its caller abort listener', async () => {
  let activeListeners = 0;
  let registeredListener;
  const callerSignal = {
    aborted: false,
    addEventListener(_type, listener) {
      registeredListener = listener;
      activeListeners++;
    },
    removeEventListener(_type, listener) {
      if (listener === registeredListener) activeListeners--;
    },
  };
  const { apiFetch } = loadApiModule({
    fetchImpl: async () => jsonResponse({ done: true }),
  });
  await apiFetch('/score', { signal: callerSignal });
  assert.equal(activeListeners, 0);
});

test('timeouts can be disabled explicitly for a caller-managed request', async () => {
  const timers = createTimers();
  const { apiFetch } = loadApiModule({
    timers,
    fetchImpl: async () => jsonResponse({ done: true }),
  });
  await apiFetch('/score', { timeoutMs: null });
  assert.equal(timers.delays.length, 0);
});

test('invalid timeout values fail before fetch and remove the caller listener', async () => {
  let fetchCalls = 0;
  let listeners = 0;
  const callerSignal = {
    aborted: false,
    addEventListener() { listeners++; },
    removeEventListener() { listeners--; },
  };
  const { apiFetch } = loadApiModule({
    fetchImpl: async () => { fetchCalls++; return jsonResponse({}); },
  });

  await assert.rejects(apiFetch('/score', { timeoutMs: -1, signal: callerSignal }), TypeError);
  assert.equal(fetchCalls, 0);
  assert.equal(listeners, 0);
});

test('the first abort source deterministically wins caller-timeout races', async () => {
  {
    const timers = createTimers();
    const caller = new AbortController();
    const { apiFetch, ApiCancellationError } = loadApiModule({
      timers,
      fetchImpl: async (_url, { signal }) => rejectWhenAborted(signal),
    });
    const request = apiFetch('/score', { signal: caller.signal, timeoutMs: 10 });
    caller.abort();
    timers.runNext();
    await assert.rejects(request, ApiCancellationError);
  }

  {
    const timers = createTimers();
    const caller = new AbortController();
    const { apiFetch, ApiTimeoutError } = loadApiModule({
      timers,
      fetchImpl: async (_url, { signal }) => rejectWhenAborted(signal),
    });
    const request = apiFetch('/score', { signal: caller.signal, timeoutMs: 10 });
    timers.runNext();
    caller.abort();
    await assert.rejects(request, ApiTimeoutError);
  }
});

test('custom headers are preserved alongside authentication and JSON headers', async () => {
  let requestOptions;
  const { api } = loadApiModule({
    token: 'token-123',
    fetchImpl: async (_url, options) => {
      requestOptions = options;
      return jsonResponse({ score: 88 });
    },
  });

  await api.getScore({ headers: { 'X-Request-ID': 'request-1' } });
  assert.equal(requestOptions.headers.Authorization, 'Bearer token-123');
  assert.equal(requestOptions.headers['Content-Type'], 'application/json');
  assert.equal(requestOptions.headers['X-Request-ID'], 'request-1');
});

test('getScan falls back to the scan list after an HTTP compatibility failure', async () => {
  const urls = [];
  const { api } = loadApiModule({
    fetchImpl: async (url) => {
      urls.push(url);
      if (urls.length === 1) return jsonResponse(null, { ok: false, status: 404, statusText: 'Not Found' });
      return jsonResponse({ scans: [{ scan_id: 'scan-1', status: 'running' }] });
    },
  });

  assert.deepEqual(await api.getScan('scan-1'), { scan_id: 'scan-1', status: 'running' });
  assert.equal(urls.length, 2);
  assert.match(urls[0], /\/scans\/scan-1$/);
  assert.match(urls[1], /\/scans$/);
});

test('getScan propagates network failures without launching a second request', async () => {
  let calls = 0;
  const { api, ApiNetworkError } = loadApiModule({
    fetchImpl: async () => { calls++; throw new TypeError('offline'); },
  });

  await assert.rejects(api.getScan('scan-1'), ApiNetworkError);
  assert.equal(calls, 1);
});

test('getScan propagates timeouts without launching a second request', async () => {
  const timers = createTimers();
  let calls = 0;
  const { api, ApiTimeoutError } = loadApiModule({
    timers,
    fetchImpl: async (_url, { signal }) => { calls++; return rejectWhenAborted(signal); },
  });
  const request = api.getScan('scan-1', { timeoutMs: 50 });
  timers.runNext();

  await assert.rejects(request, ApiTimeoutError);
  assert.equal(calls, 1);
});

test('getScan propagates explicit caller cancellation', async () => {
  const caller = new AbortController();
  const { api, ApiCancellationError } = loadApiModule({
    fetchImpl: async (_url, { signal }) => rejectWhenAborted(signal),
  });
  const request = api.getScan('scan-1', { signal: caller.signal });
  caller.abort();
  await assert.rejects(request, ApiCancellationError);
});

for (const [label, response] of [
  ['HTTP', jsonResponse(null, { ok: false, status: 503, statusText: 'Unavailable' })],
  ['network', new TypeError('offline')],
]) {
  test(`getPlaybook returns empty optional data after a ${label} failure`, async () => {
    const { api } = loadApiModule({
      fetchImpl: async () => {
        if (response instanceof Error) throw response;
        return response;
      },
    });
    assert.deepEqual(await api.getPlaybook('finding-1'), {
      portalSteps: [], cliCommands: [], validationSteps: [], references: [],
    });
  });
}

test('getPlaybook returns empty optional data after a timeout', async () => {
  const timers = createTimers();
  const { api } = loadApiModule({
    timers,
    fetchImpl: async (_url, { signal }) => rejectWhenAborted(signal),
  });
  const request = api.getPlaybook('finding-1', { timeoutMs: 20 });
  timers.runNext();
  assert.deepEqual(await request, {
    portalSteps: [], cliCommands: [], validationSteps: [], references: [],
  });
});

test('getPlaybook propagates explicit caller cancellation', async () => {
  const caller = new AbortController();
  const { api, ApiCancellationError } = loadApiModule({
    fetchImpl: async (_url, { signal }) => rejectWhenAborted(signal),
  });
  const request = api.getPlaybook('finding-1', { signal: caller.signal });
  caller.abort();
  await assert.rejects(request, ApiCancellationError);
});

test('getCVESummary falls back for HTTP, network, and timeout failures', async () => {
  for (const failure of ['http', 'network', 'timeout']) {
    const timers = createTimers();
    const { api } = loadApiModule({
      timers,
      fetchImpl: async (_url, { signal }) => {
        if (failure === 'http') return jsonResponse(null, { ok: false, status: 404, statusText: 'Not Found' });
        if (failure === 'network') throw new TypeError('offline');
        return rejectWhenAborted(signal);
      },
    });
    const request = api.getCVESummary({ timeoutMs: 20 });
    if (failure === 'timeout') timers.runNext();
    assert.equal(await request, null);
  }
});

test('getCVESummary propagates explicit caller cancellation', async () => {
  const caller = new AbortController();
  const { api, ApiCancellationError } = loadApiModule({
    fetchImpl: async (_url, { signal }) => rejectWhenAborted(signal),
  });
  const request = api.getCVESummary({ signal: caller.signal });
  caller.abort();
  await assert.rejects(request, ApiCancellationError);
});

test('triggerScan is attempted once and options cannot override its POST body', async () => {
  let calls = 0;
  let requestOptions;
  const { api, ApiNetworkError } = loadApiModule({
    fetchImpl: async (_url, options) => {
      calls++;
      requestOptions = options;
      throw new TypeError('offline');
    },
  });

  await assert.rejects(api.triggerScan('sub-1', {
    method: 'GET',
    body: 'wrong',
    headers: { 'X-Request-ID': 'request-1' },
  }), ApiNetworkError);
  assert.equal(calls, 1);
  assert.equal(requestOptions.method, 'POST');
  assert.equal(requestOptions.body, JSON.stringify({ subscription_id: 'sub-1' }));
  assert.equal(requestOptions.headers['X-Request-ID'], 'request-1');
});

let failures = 0;
for (const { description, fn } of tests) {
  try {
    await fn();
    console.log(`PASS: ${description}`);
  } catch (err) {
    failures++;
    console.error(`FAIL: ${description}\n  ${err.stack || err.message}`);
  }
}

if (failures > 0) {
  console.error(`\n${failures} test(s) failed`);
  process.exit(1);
}
console.log(`\nAll ${tests.length} API request tests passed`);
