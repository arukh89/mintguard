// MintGuard — deterministic pre-signing policy, pure functions only.
//
// Design principles (documented, not hidden):
//   1. Fail closed. Anything unknown raises the risk score; nothing
//      unknown is silently trusted.
//   2. Deterministic. Same (inputs + chain facts) => same verdict, always.
//      That is the checkable claim: POST /verify recomputes it.
//   3. The policy checks WHAT the transaction does, not WHO sent it.
//      No allow-lists, no reputation, no model calls — a reviewer can
//      re-derive every point from this file alone.
//
// Scoring (policy v1). Points add; score is capped at 100.
//   UNVERIFIED_CONTRACT   +40  target not source-verified on Sourcify
//   VERIFY_UNKNOWN        +15  Sourcify check failed/timed out (not a pass)
//   UNLIMITED_APPROVAL    +45  approve() amount >= 2**255
//   APPROVAL_GRANTED      +10  any approve() with amount > 0
//   SET_APPROVAL_FOR_ALL  +40  setApprovalForAll(true)
//   PERMIT                +25  EIP-2612 permit (off-chain signed approval)
//   MULTICALL             +20  batched calls hide the real actions
//   UNKNOWN_SELECTOR      +25  calldata function not in the known table
//   PAID_MINT             +20  mint/claim call carrying value > 0
//   HIGH_VALUE            +15  value > 0.1 BNB (1e17 wei) on chain 56
//   EMPTY_CALLDATA_VALUE  +10  plain value transfer with no calldata
//
// Verdict bands: 0-29 ALLOW, 30-59 REVIEW, 60-100 BLOCK.
'use strict';

const { createHash } = require('node:crypto');
const { SELECTORS } = require('./selectors');

const POLICY_VERSION = 'mintguard-policy-v1';
const UNLIMITED_THRESHOLD = 1n << 255n;
const HIGH_VALUE_WEI = 100000000000000000n; // 0.1 BNB

function isAddress(v) {
  return typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v);
}
function isHexData(v) {
  return typeof v === 'string' && /^0x([0-9a-fA-F]{2})*$/.test(v);
}
function parseValue(v) {
  if (v === undefined || v === null || v === '') return 0n;
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number' && Number.isInteger(v) && v >= 0) return BigInt(v);
  if (typeof v === 'string' && /^(0x[0-9a-fA-F]+|\d+)$/.test(v)) return BigInt(v);
  return null;
}

// Canonical input object: exactly what the verdict is computed from.
// inputsHash = sha256 of this JSON. Any change to an input changes the hash.
function canonicalInputs({ chainId, to, data, value }) {
  return {
    chainId: Number(chainId) || 56,
    data: (data || '0x').toLowerCase(),
    to: (to || '').toLowerCase(),
    value: (value ?? '0').toString(),
  };
}
function inputsHash(inputs) {
  return createHash('sha256').update(JSON.stringify(canonicalInputs(inputs))).digest('hex');
}

// Decode the first ABI word after the selector as an address (last 20 bytes)
// or as a uint256. Returns null when the calldata is too short.
function wordAsAddress(data, wordIndex) {
  const start = 2 + 8 + wordIndex * 64;
  const hex = data.slice(start, start + 64);
  if (hex.length < 64) return null;
  return '0x' + hex.slice(24);
}
function wordAsUint(data, wordIndex) {
  const start = 2 + 8 + wordIndex * 64;
  const hex = data.slice(start, start + 64);
  if (hex.length < 64) return null;
  return BigInt('0x' + hex);
}

// Pure policy: inputs + chainFacts -> { score, verdict, reasons, details }.
// chainFacts = { verified: true | false | null }  (null = Sourcify unreachable)
function decide(inputs, chainFacts) {
  const { chainId, to, data, value } = canonicalInputs(inputs);
  const valueWei = parseValue(value);
  const reasons = [];
  const details = {};
  let score = 0;
  const add = (points, code, extra) => {
    score += points;
    reasons.push(code);
    if (extra !== undefined) details[code] = extra;
  };

  // --- chain facts -------------------------------------------------------
  if (chainFacts && chainFacts.verified === false) add(40, 'UNVERIFIED_CONTRACT');
  else if (!chainFacts || chainFacts.verified === null || chainFacts.verified === undefined) {
    add(15, 'VERIFY_UNKNOWN');
  }
  details.contractVerified = chainFacts ? chainFacts.verified : null;

  // --- calldata ----------------------------------------------------------
  const selector = data.length >= 10 ? data.slice(0, 10) : null;
  const fn = selector ? SELECTORS[selector] : null;
  details.selector = selector;
  details.function = fn ? fn.name : null;

  if (!data || data === '0x') {
    if (valueWei > 0n) add(10, 'EMPTY_CALLDATA_VALUE');
  } else if (!fn) {
    add(25, 'UNKNOWN_SELECTOR');
  } else if (fn.kind === 'approval') {
    const amount = wordAsUint(data, 1);
    const spender = wordAsAddress(data, 0);
    details.spender = spender;
    details.amount = amount === null ? null : amount.toString();
    if (amount !== null && amount >= UNLIMITED_THRESHOLD) add(45, 'UNLIMITED_APPROVAL');
    else if (amount !== null && amount > 0n) add(10, 'APPROVAL_GRANTED');
    else if (amount === 0n) add(0, 'APPROVAL_ZERO');
  } else if (fn.kind === 'approval_all') {
    const approved = wordAsUint(data, 1);
    details.operator = wordAsAddress(data, 0);
    if (approved === 1n) add(40, 'SET_APPROVAL_FOR_ALL');
  } else if (fn.kind === 'permit') {
    add(25, 'PERMIT');
  } else if (fn.kind === 'multicall') {
    add(20, 'MULTICALL');
  } else if (fn.kind === 'mint' || fn.kind === 'claim') {
    if (valueWei > 0n) add(20, 'PAID_MINT', { valueWei: valueWei.toString() });
    const qty = wordAsUint(data, fn.name.includes('(uint256)') ? 0 : 1);
    if (qty !== null) details.quantity = qty.toString();
  }
  // transfer / transferFrom: no points by themselves; value + target checks below.

  // --- value ---------------------------------------------------------------
  if (chainId === 56 && valueWei > HIGH_VALUE_WEI) add(15, 'HIGH_VALUE', { valueWei: valueWei.toString() });

  if (score > 100) score = 100;
  const verdict = score < 30 ? 'ALLOW' : score < 60 ? 'REVIEW' : 'BLOCK';
  return { score, verdict, reasons, details };
}

// Validate raw request input. Returns { ok, inputs } or { ok:false, error }.
function validate(raw) {
  if (!raw || typeof raw !== 'object') return { ok: false, error: 'body must be a JSON object' };
  const { chainId, to, data, value } = raw;
  if (!isAddress(to)) return { ok: false, error: 'to must be a 0x-prefixed 40-hex-char address' };
  if (data !== undefined && data !== null && !isHexData(data)) {
    return { ok: false, error: 'data must be 0x-prefixed even-length hex' };
  }
  if (value !== undefined && value !== null && parseValue(value) === null) {
    return { ok: false, error: 'value must be a non-negative integer (decimal or 0x hex string)' };
  }
  if (value !== undefined && value !== null && parseValue(value) < 0n) {
    return { ok: false, error: 'value must be non-negative' };
  }
  const cid = chainId === undefined || chainId === null ? 56 : Number(chainId);
  if (!Number.isInteger(cid) || cid <= 0) return { ok: false, error: 'chainId must be a positive integer' };
  return { ok: true, inputs: { chainId: cid, to, data: data || '0x', value: value === undefined || value === null ? '0' : String(value) } };
}

module.exports = {
  POLICY_VERSION,
  canonicalInputs,
  inputsHash,
  decide,
  validate,
};
