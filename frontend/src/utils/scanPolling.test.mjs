import assert from 'node:assert/strict';
import { pollScan } from './scanPolling.js';

const noWait = async () => {};

const tests = [];
function test(description, fn) { tests.push({ description, fn }); }

test('transient network and timeout errors do not terminate a healthy polling sequence', async () => {
  const outcomes = [
    Object.assign(new Error('offline'), { code: 'NETWORK_ERROR' }),
    { scan_id: 'scan-1', status: 'running' },
    Object.assign(new Error('slow'), { code: 'TIMEOUT' }),
    { scan_id: 'scan-1', status: 'completed', total_findings: 3 },
  ];
  let calls = 0;

  const result = await pollScan({
    scanId: 'scan-1',
    getScan: async () => {
      const outcome = outcomes[calls++];
      if (outcome instanceof Error) throw outcome;
      return outcome;
    },
    wait: noWait,
    maxAttempts: outcomes.length,
  });

  assert.equal(calls, 4);
  assert.equal(result.status, 'completed');
  assert.equal(result.total_findings, 3);
});

test('explicit caller cancellation stops polling immediately', async () => {
  const controller = new AbortController();
  let calls = 0;
  let markStarted;
  const started = new Promise((resolve) => { markStarted = resolve; });

  const polling = pollScan({
    scanId: 'scan-1',
    requestOptions: { signal: controller.signal },
    getScan: async (_scanId, { signal }) => {
      calls++;
      markStarted();
      return new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => {
          reject(Object.assign(new Error('cancelled'), { code: 'CANCELLED' }));
        }, { once: true });
      });
    },
    wait: noWait,
  });

  await started;
  controller.abort();
  await assert.rejects(polling, (err) => err.code === 'CANCELLED');

  assert.equal(calls, 1);
});

test('a real backend failed status is returned as terminal state', async () => {
  const failed = { scan_id: 'scan-1', status: 'failed' };
  const result = await pollScan({
    scanId: 'scan-1',
    getScan: async () => failed,
    wait: noWait,
  });

  assert.equal(result, failed);
});

test('polling returns null after the configured attempt limit', async () => {
  let calls = 0;
  const result = await pollScan({
    scanId: 'scan-1',
    getScan: async () => { calls++; return { scan_id: 'scan-1', status: 'running' }; },
    wait: noWait,
    maxAttempts: 3,
  });

  assert.equal(calls, 3);
  assert.equal(result, null);
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
console.log(`\nAll ${tests.length} scan polling tests passed`);
