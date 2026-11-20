// HTTP routing for MintGuard — framework-free, shared by the local
// server (server.js) and the Vercel serverless entry (api/index.js).
//
// Endpoints:
//   GET  /            demo page (HTML form that calls /analyze)
//   GET  /health      { ok, policy, time }
//   GET  /policy      the scoring table, verbatim from the policy
//   POST /analyze     { chainId?, to, data?, value? } -> verdict + receipt
//   POST /verify      { inputs, chainFacts, verdict } -> recomputation check
'use strict';

const { POLICY_VERSION, canonicalInputs, inputsHash, decide, validate } = require('./guard');
const { checkVerified } = require('./sourcify');
const { signReceipt, verifyReceipt, isDevSecret } = require('./receipt');
const { SELECTORS } = require('./selectors');

const POLICY_TABLE = [
  { code: 'UNVERIFIED_CONTRACT', points: 40, when: 'target contract has no verified source on Sourcify' },
  { code: 'VERIFY_UNKNOWN', points: 15, when: 'Sourcify check failed or timed out (not treated as verified)' },
  { code: 'UNLIMITED_APPROVAL', points: 45, when: 'approve() amount >= 2^255' },
  { code: 'APPROVAL_GRANTED', points: 10, when: 'approve() with amount > 0' },
  { code: 'SET_APPROVAL_FOR_ALL', points: 40, when: 'setApprovalForAll(true)' },
  { code: 'PERMIT', points: 25, when: 'EIP-2612 permit() call' },
  { code: 'MULTICALL', points: 20, when: 'multicall() batch hides the real actions' },
  { code: 'UNKNOWN_SELECTOR', points: 25, when: 'calldata function is not in the known table' },
  { code: 'PAID_MINT', points: 20, when: 'mint/claim call carrying value > 0' },
  { code: 'HIGH_VALUE', points: 15, when: 'value > 0.1 BNB on BSC (chain 56)' },
  { code: 'EMPTY_CALLDATA_VALUE', points: 10, when: 'plain value transfer with no calldata' },
];

function json(status, obj) {
  return { status, headers: { 'content-type': 'application/json; charset=utf-8' }, body: JSON.stringify(obj) };
}

async function analyze(raw, fetchFn) {
  const v = validate(raw);
  if (!v.ok) return json(400, { ok: false, error: v.error });
  const inputs = canonicalInputs(v.inputs);
  const facts = await checkVerified(inputs.chainId, inputs.to, fetchFn || fetch);
  const d = decide(inputs, facts);
  const hash = inputsHash(inputs);
  const payload = { policy: POLICY_VERSION, inputsHash: hash, verdict: d.verdict, score: d.score };
  const receipt = signReceipt(payload);
  return json(200, {
    ok: true,
    agent: 'mintguard',
    policy: POLICY_VERSION,
    inputs,
    inputsHash: hash,
    contract: { address: inputs.to, verified: facts.verified, source: facts.source, note: facts.note || null },
    decision: d,
    receipt,
    receiptDevSecret: isDevSecret(),
    verify: { hint: 'POST the inputs + chainFacts {verified} + verdict to /verify to recompute this verdict' },
  });
}

async function verify(raw) {
  if (!raw || typeof raw !== 'object') return json(400, { ok: false, error: 'body must be a JSON object' });
  const { inputs, chainFacts, verdict, receipt } = raw;
  const v = validate(inputs || {});
  if (!v.ok) return json(400, { ok: false, error: 'inputs: ' + v.error });
  const canon = canonicalInputs(v.inputs);
  const facts = chainFacts && typeof chainFacts === 'object' ? { verified: chainFacts.verified ?? null } : { verified: null };
  const d = decide(canon, facts);
  const hash = inputsHash(canon);
  const payload = { policy: POLICY_VERSION, inputsHash: hash, verdict: d.verdict, score: d.score };
  const receiptValid = receipt === undefined ? null : verifyReceipt(payload, receipt);
  return json(200, {
    ok: true,
    recomputed: d,
    inputsHash: hash,
    verdictMatches: verdict === undefined ? null : verdict === d.verdict,
    receiptValid,
    note: 'Recomputation proves the verdict follows from the inputs + recorded chain facts under this policy version. It does not re-prove the chain facts themselves.',
  });
}

function demoPage() {
  const examples = [
    { label: 'Free mint (verified contract, value 0)', to: '0x0000000000000000000000000000000000000000', data: '0xa0712d68' + '0000000000000000000000000000000000000000000000000000000000000001', value: '0' },
  ];
  return `<!doctype html><html><head><meta charset="utf-8"><title>MintGuard — pre-signing guard for BSC agent transactions</title>
<style>body{font-family:system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 16px}input,textarea{width:100%;padding:8px;margin:4px 0}button{padding:10px 18px}pre{background:#111;color:#0f0;padding:12px;overflow:auto}</style></head>
<body><h1>MintGuard</h1>
<p>Pre-signing guard for BSC/EVM agent transactions. Paste a transaction, get a deterministic verdict (ALLOW / REVIEW / BLOCK) with reasons, a risk score, and a signed receipt. Same inputs always give the same verdict — recompute it at <code>POST /verify</code>.</p>
<p>Wildcard entry, zkVerify Agent Games Season 01. Policy: <a href="/policy">/policy</a>. Health: <a href="/health">/health</a>.</p>
<form id="f"><label>to (contract)<input name="to" value="0x0000000000000000000000000000000000000000"></label>
<label>data (calldata)<input name="data" value="0xa0712d68${'0'.repeat(63)}1"></label>
<label>value (wei)<input name="value" value="0"></label>
<label>chainId<input name="chainId" value="56"></label><button type="submit">Analyze</button></form>
<pre id="out">Result appears here.</pre>
<script>document.getElementById('f').addEventListener('submit',async e=>{e.preventDefault();const fd=new FormData(e.target);const body={to:fd.get('to'),data:fd.get('data'),value:fd.get('value'),chainId:Number(fd.get('chainId'))};const r=await fetch('/analyze',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});document.getElementById('out').textContent=JSON.stringify(await r.json(),null,2);});</script>
</body></html>`;
}

async function handle(method, path, body, fetchFn) {
  const p = (path || '/').split('?')[0].replace(/\/$/, '') || '/';
  if (method === 'GET' && p === '/') {
    return { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' }, body: demoPage() };
  }
  if (method === 'GET' && p === '/health') {
    return json(200, { ok: true, agent: 'mintguard', policy: POLICY_VERSION, time: new Date().toISOString() });
  }
  if (method === 'GET' && p === '/policy') {
    return json(200, { ok: true, policy: POLICY_VERSION, verdictBands: { ALLOW: '0-29', REVIEW: '30-59', BLOCK: '60-100' }, table: POLICY_TABLE, knownSelectors: SELECTORS });
  }
  if (method === 'POST' && p === '/analyze') return analyze(body, fetchFn);
  if (method === 'POST' && p === '/verify') return verify(body);
  return json(404, { ok: false, error: 'not found: ' + method + ' ' + p });
}

module.exports = { handle, POLICY_TABLE };
