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
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>MintGuard — pre-signing guard for BSC agent transactions</title>
<style>
:root{--bg:#0b0f14;--card:#121826;--line:#243044;--text:#e6edf3;--muted:#9aa7b8;--accent:#58a6ff;--green:#22c55e;--amber:#f59e0b;--red:#ef4444}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);margin:0;padding:0 16px 48px}
.wrap{max-width:880px;margin:0 auto}
header{padding:32px 0 8px}
h1{margin:0;font-size:32px}
h1 span{color:var(--accent)}
.tag{color:var(--muted);margin:8px 0 0}
.badges{margin:14px 0 0;display:flex;gap:8px;flex-wrap:wrap}
.badge{border:1px solid var(--line);border-radius:999px;padding:4px 10px;font-size:12px;color:var(--muted)}
.badge a{color:var(--accent);text-decoration:none}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin-top:20px}
h2{margin:0 0 4px;font-size:18px}
.sub{color:var(--muted);font-size:14px;margin:0 0 16px}
label{display:block;font-size:13px;color:var(--muted);margin:12px 0 4px}
input{width:100%;padding:10px;border:1px solid var(--line);border-radius:8px;background:#0b0f14;color:var(--text);font-family:ui-monospace,monospace;font-size:13px}
.row{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px;align-items:center}
button{padding:10px 18px;border-radius:8px;border:1px solid var(--line);background:#1b2436;color:var(--text);cursor:pointer;font-size:14px}
button.primary{background:var(--accent);border-color:var(--accent);color:#04121f;font-weight:600}
button.chip{padding:6px 12px;font-size:13px}
button:disabled{opacity:.5;cursor:default}
.examples{margin-top:14px;font-size:13px;color:var(--muted)}
#verdict{border-radius:10px;padding:16px;margin:0 0 12px;font-size:22px;font-weight:700}
#verdict small{display:block;font-size:13px;font-weight:400;margin-top:4px;opacity:.85}
.gauge{position:relative;height:14px;border-radius:999px;background:#0b0f14;border:1px solid var(--line);margin:10px 0 4px}
#gauge-fill{height:100%;border-radius:999px;width:0%}
.tick{position:absolute;top:-4px;bottom:-4px;width:2px;background:var(--muted)}
.gauge-labels{display:flex;justify-content:space-between;font-size:12px;color:var(--muted)}
table{width:100%;border-collapse:collapse;font-size:14px}
td,th{border-bottom:1px solid var(--line);padding:8px 6px;text-align:left;vertical-align:top}
th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
code{font-family:ui-monospace,monospace;font-size:13px}
.mono{font-family:ui-monospace,monospace;font-size:13px;word-break:break-all}
.muted{color:var(--muted)}
details{margin-top:12px}
pre{background:#0b0f14;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;font-size:12px}
footer{margin-top:28px;color:var(--muted);font-size:13px}
footer a{color:var(--accent)}
</style></head>
<body><div class="wrap">
<header><h1>Mint<span>Guard</span></h1>
<p class="tag">Pre-signing guard for BSC / EVM agent transactions. Paste a transaction, get a deterministic verdict — ALLOW, REVIEW or BLOCK — with a risk score, named reasons, and a signed receipt. Same inputs always give the same verdict.</p>
<div class="badges"><span class="badge">Wildcard entry · zkVerify Agent Games Season 01</span><span class="badge">Policy mintguard-policy-v1</span><span class="badge"><a href="https://github.com/arukh89/mintguard">GitHub</a></span><span class="badge"><a href="https://dev.to/arukh89/before-i-let-my-agent-sign-anything-i-make-it-prove-the-verdict-building-mintguard-for-zkverify-2e6e">Build log</a></span><span class="badge"><a href="/policy">Policy</a></span><span class="badge"><a href="/health">Health</a></span></div></header>

<section class="card"><h2>Try it — analyze a transaction</h2>
<p class="sub">The guard decodes the calldata, checks the target contract on Sourcify, and scores it. Nothing is signed here — this is the check that runs before a signature.</p>
<form id="f">
<label>to (contract address)<input id="to" name="to" value="0xb8164afefc53910d7a74cece15a60a9e0c86089e"></label>
<label>data (calldata)<input id="data" name="data" value="0xa0712d680000000000000000000000000000000000000000000000000000000000000001"></label>
<label>value (wei)<input id="value" name="value" value="0"></label>
<label>chainId<input id="chainId" name="chainId" value="56"></label>
<div class="row"><button class="primary" type="submit">Analyze</button><button type="button" id="copy-curl">Copy as cURL</button><button type="button" id="share">Copy share link</button></div>
</form>
<div class="examples">One click, three real shapes:
<button class="chip" type="button" data-ex="mint">Free mint → ALLOW</button>
<button class="chip" type="button" data-ex="approve">Unlimited approve → BLOCK</button>
<button class="chip" type="button" data-ex="approvalForAll">setApprovalForAll → REVIEW</button>
</div></section>

<section class="card" id="result-card" style="display:none"><h2>Verdict</h2>
<div id="verdict"></div>
<div class="gauge"><div id="gauge-fill"></div><div class="tick" style="left:30%"></div><div class="tick" style="left:60%"></div></div>
<div class="gauge-labels"><span>0 ALLOW</span><span>30 REVIEW</span><span>60 BLOCK</span><span>100</span></div>
<p id="contract-line" class="mono" style="margin-top:14px"></p>
<table><thead><tr><th>Reason</th><th>Points</th><th>What it means</th></tr></thead><tbody id="reasons-body"></tbody></table>
<p class="mono" id="receipt-line" style="margin-top:14px"></p>
<div class="row"><button type="button" id="verify-btn">Verify receipt</button><span id="verify-out" class="mono"></span></div>
<details><summary>Raw JSON response</summary><pre id="raw"></pre></details>
</section>

<section class="card"><h2>How it scores</h2>
<p class="sub">ALLOW 0–29 · REVIEW 30–59 · BLOCK 60–100</p>
<table><thead><tr><th>Rule</th><th>Points</th><th>When</th></tr></thead><tbody id="policy-body"><tr><td colspan="3">Loading /policy…</td></tr></tbody></table>
<p class="sub" style="margin-top:12px">Fail closed: anything unknown raises the score. Unknown is never silently trusted. Deterministic: the same inputs always give the same verdict — recompute any verdict at <code>POST /verify</code>.</p></section>

<section class="card"><h2>Verified, not just claimed</h2>
<p class="sub">The verdict is a checkable claim today: deterministic recomputation plus a signed HMAC receipt (try “Verify receipt” above). On top of that, the verdict is proven in zero knowledge against the tournament’s official gatekeeper circuit:</p>
<ul>
<li>ALLOW, score 0 — Groth16 proof verifies in 885 ms</li>
<li>BLOCK, score 85 — Groth16 proof verifies in 303 ms</li>
<li>Verification key: <span class="mono">0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0</span></li>
<li>Proofs + one-command re-verifier in the repo: <code>circuits/proof-allow-score0.json</code>, <code>circuits/proof-block-score85.json</code>, <code>node scripts/verify-proof.js</code></li>
</ul>
<p class="sub">Honest limit: the proof covers the encoded verdict, not the Sourcify lookup or selector decoding — those happen outside the circuit.</p></section>

<footer>Built for the zkVerify Agent Games Season 01 — Wildcard + Creator Track. Source: <a href="https://github.com/arukh89/mintguard">github.com/arukh89/mintguard</a> (MIT). Build log: <a href="https://dev.to/arukh89/before-i-let-my-agent-sign-anything-i-make-it-prove-the-verdict-building-mintguard-for-zkverify-2e6e">dev.to</a>.</footer>
</div>
<script>
var policyTable = null;
var lastResult = null;
function esc(s){ return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
function bandColor(v){ return v === 'ALLOW' ? '#22c55e' : v === 'REVIEW' ? '#f59e0b' : '#ef4444'; }
function reasonInfo(code){
  if (policyTable) { for (var i = 0; i < policyTable.length; i++) { if (policyTable[i].code === code) return policyTable[i]; } }
  return { code: code, points: null, when: '' };
}
function loadPolicy(){
  fetch('/policy').then(function (r) { return r.json(); }).then(function (j) {
    policyTable = j.table || null;
    var tb = document.getElementById('policy-body');
    if (policyTable) {
      var html = '';
      for (var i = 0; i < policyTable.length; i++) {
        var row = policyTable[i];
        html += '<tr><td><code>' + esc(row.code) + '</code></td><td>+' + row.points + '</td><td>' + esc(row.when) + '</td></tr>';
      }
      tb.innerHTML = html;
    } else { tb.innerHTML = '<tr><td colspan="3">Policy table is empty.</td></tr>'; }
  }).catch(function () {
    document.getElementById('policy-body').innerHTML = '<tr><td colspan="3">Could not load /policy — the endpoint may be unreachable.</td></tr>';
  });
}
function readForm(){
  return { to: document.getElementById('to').value.trim(), data: document.getElementById('data').value.trim(), value: document.getElementById('value').value.trim(), chainId: Number(document.getElementById('chainId').value) };
}
var EXAMPLES = {
  mint: { to: '0xb8164afefc53910d7a74cece15a60a9e0c86089e', data: '0xa0712d68' + '0'.repeat(62) + '01', value: '0', chainId: 56 },
  approve: { to: '0x1111111111111111111111111111111111111111', data: '0x095ea7b3' + '0'.repeat(24) + '1'.repeat(40) + 'f'.repeat(64), value: '0', chainId: 56 },
  approvalForAll: { to: '0xb8164afefc53910d7a74cece15a60a9e0c86089e', data: '0xa22cb465' + '0'.repeat(24) + '1'.repeat(40) + '0'.repeat(63) + '1', value: '0', chainId: 56 }
};
function fillExample(name){
  var ex = EXAMPLES[name];
  if (!ex) return;
  document.getElementById('to').value = ex.to;
  document.getElementById('data').value = ex.data;
  document.getElementById('value').value = ex.value;
  document.getElementById('chainId').value = ex.chainId;
  analyze();
}
function renderResult(j){
  var d = j.decision;
  var card = document.getElementById('result-card');
  card.style.display = 'block';
  var v = document.getElementById('verdict');
  var color = bandColor(d.verdict);
  v.style.background = color;
  v.style.color = '#04121f';
  v.innerHTML = esc(d.verdict) + ' · score ' + d.score + '<small>' + (d.details && d.details.function ? 'Function: ' + esc(d.details.function) : 'No known function') + '</small>';
  document.getElementById('gauge-fill').style.width = d.score + '%';
  document.getElementById('gauge-fill').style.background = color;
  var c = j.contract;
  var vtxt = c.verified === true ? 'Verified on Sourcify' : c.verified === false ? 'NOT verified on Sourcify' : 'Verification check failed — treated as unknown';
  document.getElementById('contract-line').textContent = 'Contract ' + c.address + ' — ' + vtxt + (c.source ? ' (' + c.source + ')' : '');
  var rb = document.getElementById('reasons-body');
  var html = '';
  for (var i = 0; i < d.reasons.length; i++) {
    var info = reasonInfo(d.reasons[i]);
    html += '<tr><td><code>' + esc(info.code) + '</code></td><td>' + (info.points === null ? '—' : '+' + info.points) + '</td><td>' + esc(info.when) + '</td></tr>';
  }
  if (!d.reasons.length) html = '<tr><td colspan="3">No risk reasons — nothing to object to.</td></tr>';
  rb.innerHTML = html;
  document.getElementById('receipt-line').textContent = 'Receipt (HMAC-SHA256): ' + j.receipt.slice(0, 24) + '…' + (j.receiptDevSecret ? ' — signed with the DEV secret, proves nothing' : ' — signed with the production secret');
  document.getElementById('verify-out').textContent = '';
  document.getElementById('raw').textContent = JSON.stringify(j, null, 2);
  card.scrollIntoView();
}
function showError(msg){
  var card = document.getElementById('result-card');
  card.style.display = 'block';
  var v = document.getElementById('verdict');
  v.style.background = '#ef4444';
  v.style.color = '#04121f';
  v.textContent = 'Error: ' + msg;
  document.getElementById('gauge-fill').style.width = '0%';
  document.getElementById('contract-line').textContent = '';
  document.getElementById('reasons-body').innerHTML = '';
  document.getElementById('receipt-line').textContent = '';
  document.getElementById('verify-out').textContent = '';
  document.getElementById('raw').textContent = '';
}
function analyze(){
  var body = readForm();
  document.getElementById('verify-out').textContent = '';
  fetch('/analyze', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
    .then(function (r) { return r.json(); })
    .then(function (j) {
      if (!j.ok) { showError(j.error || 'Analyze failed'); return; }
      lastResult = j;
      renderResult(j);
    })
    .catch(function (e) { showError(String(e && e.message ? e.message : e)); });
}
function verifyReceipt(){
  if (!lastResult) return;
  var out = document.getElementById('verify-out');
  out.textContent = 'Verifying…';
  var payload = { inputs: lastResult.inputs, chainFacts: { verified: lastResult.contract.verified }, verdict: lastResult.decision.verdict, receipt: lastResult.receipt };
  fetch('/verify', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) })
    .then(function (r) { return r.json(); })
    .then(function (j) {
      if (!j.ok) { out.textContent = 'Verify failed: ' + (j.error || 'unknown'); return; }
      out.textContent = 'verdictMatches: ' + j.verdictMatches + ' · receiptValid: ' + j.receiptValid + ' · recomputed: ' + j.recomputed.verdict + ' ' + j.recomputed.score;
    })
    .catch(function (e) { out.textContent = 'Verify failed: ' + String(e && e.message ? e.message : e); });
}
function copyText(t, done){
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(t).then(done, function () { fallbackCopy(t, done); });
  } else { fallbackCopy(t, done); }
}
function fallbackCopy(t, done){
  var ta = document.createElement('textarea');
  ta.value = t;
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); } catch (e) {}
  document.body.removeChild(ta);
  done();
}
function curlCommand(){
  var b = readForm();
  return "curl -s -X POST " + location.origin + "/analyze -H 'content-type: application/json' -d '" + JSON.stringify(b) + "'";
}
function shareLink(){
  var b = readForm();
  return location.origin + location.pathname + '#to=' + encodeURIComponent(b.to) + '&data=' + encodeURIComponent(b.data) + '&value=' + encodeURIComponent(b.value) + '&chainId=' + b.chainId;
}
function loadHash(){
  if (!location.hash || location.hash.length < 2) return false;
  var parts = location.hash.slice(1).split('&');
  var got = false;
  for (var i = 0; i < parts.length; i++) {
    var kv = parts[i].split('=');
    if (kv.length !== 2) continue;
    var k = decodeURIComponent(kv[0]);
    var v = decodeURIComponent(kv[1]);
    if (k === 'to' || k === 'data' || k === 'value' || k === 'chainId') {
      document.getElementById(k).value = v;
      got = true;
    }
  }
  return got;
}
document.getElementById('f').addEventListener('submit', function (e) { e.preventDefault(); analyze(); });
document.getElementById('verify-btn').addEventListener('click', verifyReceipt);
document.getElementById('copy-curl').addEventListener('click', function () {
  var btn = document.getElementById('copy-curl');
  copyText(curlCommand(), function () { btn.textContent = 'Copied!'; setTimeout(function () { btn.textContent = 'Copy as cURL'; }, 1500); });
});
document.getElementById('share').addEventListener('click', function () {
  var btn = document.getElementById('share');
  copyText(shareLink(), function () { btn.textContent = 'Link copied!'; setTimeout(function () { btn.textContent = 'Copy share link'; }, 1500); });
});
var chips = document.querySelectorAll('[data-ex]');
for (var i = 0; i < chips.length; i++) {
  chips[i].addEventListener('click', function (e) { fillExample(e.target.getAttribute('data-ex')); });
}
loadPolicy();
if (loadHash()) analyze();
</script>
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
