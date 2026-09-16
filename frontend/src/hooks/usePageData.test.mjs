import assert from 'node:assert/strict';
import {
  createPageDataLoader,
  initialPageDataState,
  pageDataReducer,
  schedulePageDataLoad,
} from './usePageData.js';

function createHarness(load) {
  let state = initialPageDataState;
  const transitions = [];
  const dispatch = (action) => {
    state = pageDataReducer(state, action);
    transitions.push(state);
  };
  return {
    loader: createPageDataLoader(load, dispatch),
    getState: () => state,
    transitions,
  };
}

const tests = [];
function test(description, fn) { tests.push({ description, fn }); }

test('a successful populated load transitions from loading to success', async () => {
  const data = [{ id: 1 }];
  const harness = createHarness(async () => data);
  await harness.loader.retry();
  assert.deepEqual(harness.transitions.map(({ status }) => status), ['loading', 'success']);
  assert.equal(harness.getState().data, data);
});

test('a successful empty load remains distinct from loading', async () => {
  const harness = createHarness(async () => []);
  await harness.loader.retry();
  assert.equal(harness.getState().status, 'success');
  assert.deepEqual(harness.getState().data, []);
});

test('a rejected load transitions to an observable error state', async () => {
  const error = new Error('backend unavailable');
  const harness = createHarness(async () => { throw error; });
  await harness.loader.retry();
  assert.equal(harness.getState().status, 'error');
  assert.equal(harness.getState().error, error);
  assert.equal(harness.getState().data, null);
});

test('retry clears the failure and can transition to populated success', async () => {
  let attempt = 0;
  const harness = createHarness(async () => {
    attempt++;
    if (attempt === 1) throw new Error('temporary failure');
    return [{ id: 'recovered' }];
  });
  await harness.loader.retry();
  await harness.loader.retry();
  assert.deepEqual(
    harness.transitions.map(({ status }) => status),
    ['loading', 'error', 'loading', 'success'],
  );
  assert.deepEqual(harness.getState().data, [{ id: 'recovered' }]);
});

test('retry can recover to a successful empty response', async () => {
  let attempt = 0;
  const harness = createHarness(async () => {
    attempt++;
    if (attempt === 1) throw new Error('temporary failure');
    return [];
  });
  await harness.loader.retry();
  await harness.loader.retry();
  assert.equal(harness.getState().status, 'success');
  assert.deepEqual(harness.getState().data, []);
});

test('rapid retry attempts do not start duplicate concurrent requests', async () => {
  let resolveLoad;
  let calls = 0;
  const harness = createHarness(() => {
    calls++;
    return new Promise((resolve) => { resolveLoad = resolve; });
  });
  const first = harness.loader.retry();
  await harness.loader.retry();
  assert.equal(calls, 1);
  resolveLoad('done');
  await first;
  assert.equal(harness.getState().status, 'success');
});

test('cancelled loads cannot overwrite state after unmount', async () => {
  let resolveLoad;
  const harness = createHarness(() => new Promise((resolve) => { resolveLoad = resolve; }));
  const request = harness.loader.retry();
  harness.loader.cancel();
  resolveLoad('stale');
  await request;
  assert.deepEqual(harness.transitions.map(({ status }) => status), ['loading']);
});

test('Strict Mode effect replay starts only one initial request', async () => {
  let calls = 0;
  let resolveLoad;
  const harness = createHarness(() => {
    calls++;
    return new Promise((resolve) => { resolveLoad = resolve; });
  });

  const cancelFirstSetup = schedulePageDataLoad(harness.loader);
  cancelFirstSetup();
  const cancelSecondSetup = schedulePageDataLoad(harness.loader);
  await new Promise((resolve) => queueMicrotask(resolve));

  assert.equal(calls, 1);
  cancelSecondSetup();
  resolveLoad('stale');
  await new Promise((resolve) => queueMicrotask(resolve));
  assert.deepEqual(harness.transitions.map(({ status }) => status), ['loading']);
});

let failures = 0;
for (const { description, fn } of tests) {
  try {
    await fn();
    console.log(`PASS: ${description}`);
  } catch (error) {
    failures++;
    console.error(`FAIL: ${description}\n  ${error.stack || error.message}`);
  }
}

if (failures > 0) {
  console.error(`\n${failures} test(s) failed`);
  process.exit(1);
}
console.log(`\nAll ${tests.length} page data tests passed`);
