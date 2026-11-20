// Sourcify v2 verification check (BSC default, chain 56).
// Uses the documented v2 endpoint with field selection; v1 is removed.
//   GET https://sourcify.dev/server/v2/contract/{chainId}/{address}?fields=metadata
// 200 => verified (source + metadata on record). 404 => not verified.
// Any other outcome (timeout, 5xx, network error) => null (unknown).
// Unknown is NOT a pass: the policy scores it +15 (VERIFY_UNKNOWN) and
// never treats it as verified. fail-closed by construction.
'use strict';

const SOURCIFY_BASE = 'https://sourcify.dev/server/v2/contract';

async function checkVerified(chainId, address, fetchFn = fetch, timeoutMs = 5000) {
  const url = `${SOURCIFY_BASE}/${chainId}/${address}?fields=metadata`;
  try {
    const res = await fetchFn(url, { signal: AbortSignal.timeout(timeoutMs) });
    if (res.status === 200) return { verified: true, source: 'sourcify-v2' };
    if (res.status === 404) return { verified: false, source: 'sourcify-v2' };
    return { verified: null, source: 'sourcify-v2', note: `http-${res.status}` };
  } catch (e) {
    return { verified: null, source: 'sourcify-v2', note: String(e && e.name ? e.name : e) };
  }
}

module.exports = { checkVerified, SOURCIFY_BASE };
