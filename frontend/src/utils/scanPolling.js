const TRANSIENT_ERROR_CODES = new Set(['NETWORK_ERROR', 'TIMEOUT']);

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function pollScan({
  scanId,
  getScan,
  requestOptions = {},
  wait = delay,
  intervalMs = 4000,
  maxAttempts = 75,
}) {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    await wait(intervalMs);

    try {
      const scan = await getScan(scanId, requestOptions);
      if (scan?.status === 'completed' || scan?.status === 'failed') return scan;
    } catch (err) {
      if (!TRANSIENT_ERROR_CODES.has(err?.code)) throw err;
    }
  }

  return null;
}
