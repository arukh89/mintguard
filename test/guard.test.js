// Policy tests: every scored rule, the verdict bands, determinism,
// input validation, and the /analyze + /verify round-trip (Sourcify stubbed).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { decide, validate, inputsHash, canonicalInputs } = require('../lib/guard');
const { handle } = require('../lib/handler');

const ADDR = '0x1111111111111111111111111111111111111111';
const SPENDER = '0x2222222222222222222222222222222222222222';

const pad = (hex, n = 64) => hex.replace(/^0x/, '').padStart(n, '0');
const word = (hex) => pad(hex);
const addrWord = (a) => '0'.repeat(24) + a.slice(2).toLowerCase();
const uintWord = (n) => BigInt(n).toString(16).padStart(64, '0');

const MINT1 = '0xa0712d68' + uintWord(1);
const APPROVE_UNLIMITED = '0x095ea7b3' + addrWord(SPENDER) + uintWord(1n << 255n);
const APPROVE_SMALL = '0x095ea7b3' + addrWord(SPENDER) + uintWord(100);
const APPROVE_ALL = '0xa22cb465' + addrWord(SPENDER) + uintWord(1);
const PERMIT = '0xd505accf' + addrWord(SPENDER) + addrWord(ADDR) + uintWord(100) + uintWord(999999) + uintWord(27) + word('aa'.repeat(32)) + word('bb'.repeat(32));
const MULTICALL = '0xac9650d8' + uintWord(0);
const UNKNOWN = '0xdeadbeef' + uintWord(1);

const VERIFIED = { verified: true };
const UNVERIFIED = { verified: false };
const UNKNOWN_FACTS = { verified: null };

test('verified free mint -> ALLOW, score 0', () => {
  const d = decide({ chainId: 56, to: ADDR, data: MINT1, value: '0' }, VERIFIED);
  assert.equal(d.verdict, 'ALLOW');
  assert.equal(d.score, 0);
  assert.deepEqual(d.reasons, []);
});

test('unverified contract alone -> REVIEW (40)', () => {
  const d = decide({ chainId: 56, to: ADDR, data: MINT1, value: '0' }, UNVERIFIED);
  assert.equal(d.score, 40);
  assert.equal(d.verdict, 'REVIEW');
  assert.ok(d.reasons.includes('UNVERIFIED_CONTRACT'));
});

test('unlimited approve on unverified contract -> BLOCK (40+45)', () => {
  const d = decide({ chainId: 56, to: ADDR, data: APPROVE_UNLIMITED, value: '0' }, UNVERIFIED);
  assert.equal(d.score, 85);
  assert.equal(d.verdict, 'BLOCK');
  assert.ok(d.reasons.includes('UNLIMITED_APPROVAL'));
});

test('small approve on verified contract -> ALLOW (10)', () => {
  const d = decide({ chainId: 56, to: ADDR, data: APPROVE_SMALL, value: '0' }, VERIFIED);
  assert.equal(d.score, 10);
  assert.equal(d.verdict, 'ALLOW');
});

test('setApprovalForAll(true) on verified contract -> REVIEW (40)', () => {
  const d = decide({ chainId: 56, to: ADDR, data: APPROVE_ALL, value: '0' }, VERIFIED);
  assert.equal(d.score, 40);
  assert.equal(d.verdict, 'REVIEW');
});

test('permit -> 25 points (ALLOW band) on verified contract', () => {
  const d = decide({ chainId: 56, to: ADDR, data: PERMIT, value: '0' }, VERIFIED);
  assert.equal(d.score, 25);
  assert.equal(d.verdict, 'ALLOW');
  assert.ok(d.reasons.includes('PERMIT'));
});

test('multicall -> ALLOW boundary (20)', () => {
  const d = decide({ chainId: 56, to: ADDR, data: MULTICALL, value: '0' }, VERIFIED);
  assert.equal(d.score, 20);
  assert.equal(d.verdict, 'ALLOW');
});

test('unknown selector -> ALLOW boundary (25)', () => {
  const d = decide({ chainId: 56, to: ADDR, data: UNKNOWN, value: '0' }, VERIFIED);
  assert.equal(d.score, 25);
  assert.ok(d.reasons.includes('UNKNOWN_SELECTOR'));
});

test('paid mint -> REVIEW (20)', () => {
  const d = decide({ chainId: 56, to: ADDR, data: MINT1, value: '1000000000000000' }, VERIFIED);
  assert.equal(d.score, 20);
  assert.ok(d.reasons.includes('PAID_MINT'));
});

test('high value transfer -> REVIEW (15)', () => {
  const d = decide({ chainId: 56, to: ADDR, data: '0x', value: '200000000000000000' }, VERIFIED);
  assert.ok(d.reasons.includes('HIGH_VALUE'));
  assert.equal(d.score, 25); // 15 high value + 10 empty calldata
});

test('Sourcify unreachable is not a pass (+15)', () => {
  const d = decide({ chainId: 56, to: ADDR, data: MINT1, value: '0' }, UNKNOWN_FACTS);
  assert.equal(d.score, 15);
  assert.ok(d.reasons.includes('VERIFY_UNKNOWN'));
});

test('decide is deterministic', () => {
  const inp = { chainId: 56, to: ADDR, data: APPROVE_UNLIMITED, value: '0' };
  const a = decide(inp, UNVERIFIED);
  const b = decide(inp, UNVERIFIED);
  assert.deepEqual(a, b);
  assert.equal(inputsHash(inp), inputsHash(inp));
});

test('validate rejects bad inputs', () => {
  assert.equal(validate({ to: 'not-an-address' }).ok, false);
  assert.equal(validate({ to: ADDR, data: '0xzz' }).ok, false);
  assert.equal(validate({ to: ADDR, value: '-1' }).ok, false);
  assert.equal(validate({ to: ADDR, value: 'abc' }).ok, false);
  assert.equal(validate({ to: ADDR }).ok, true);
  assert.equal(validate({ to: ADDR, data: '0x', value: '0', chainId: 56 }).ok, true);
});

// --- HTTP layer with a stubbed Sourcify fetch -------------------------------
const stubFetch = (status) => async () => ({ status });

test('/analyze round-trip with stubbed Sourcify (verified) + /verify recompute', async () => {
  const fetchFn = stubFetch(200);
  const res = await handle('POST', '/analyze', { chainId: 56, to: ADDR, data: MINT1, value: '0' }, fetchFn);
  assert.equal(res.status, 200);
  const body = JSON.parse(res.body);
  assert.equal(body.decision.verdict, 'ALLOW');
  assert.equal(body.contract.verified, true);
  assert.ok(body.receipt);

  const vres = await handle('POST', '/verify', {
    inputs: body.inputs,
    chainFacts: { verified: true },
    verdict: body.decision.verdict,
    receipt: body.receipt,
  });
  const vbody = JSON.parse(vres.body);
  assert.equal(vbody.verdictMatches, true);
  assert.equal(vbody.receiptValid, true);
  assert.equal(vbody.recomputed.verdict, 'ALLOW');
});

test('/analyze with stubbed Sourcify 404 -> UNVERIFIED_CONTRACT', async () => {
  const res = await handle('POST', '/analyze', { chainId: 56, to: ADDR, data: MINT1, value: '0' }, stubFetch(404));
  const body = JSON.parse(res.body);
  assert.equal(body.contract.verified, false);
  assert.equal(body.decision.verdict, 'REVIEW');
});

test('/analyze rejects invalid input with 400', async () => {
  const res = await handle('POST', '/analyze', { to: 'nope' }, stubFetch(200));
  assert.equal(res.status, 400);
});

test('/verify catches a wrong claimed verdict', async () => {
  const vres = await handle('POST', '/verify', {
    inputs: { chainId: 56, to: ADDR, data: APPROVE_UNLIMITED, value: '0' },
    chainFacts: { verified: false },
    verdict: 'ALLOW',
  });
  const vbody = JSON.parse(vres.body);
  assert.equal(vbody.recomputed.verdict, 'BLOCK');
  assert.equal(vbody.verdictMatches, false);
});

test('GET /health and /policy', async () => {
  const h = await handle('GET', '/health');
  assert.equal(h.status, 200);
  assert.equal(JSON.parse(h.body).ok, true);
  const p = await handle('GET', '/policy');
  assert.equal(JSON.parse(p.body).table.length, 11);
});
