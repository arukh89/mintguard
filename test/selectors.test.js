// Every selector in the runtime table must equal keccak256(signature)[0:4].
// If this test fails, the table entry is wrong and must be fixed or removed —
// never shipped on trust.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { keccak256 } = require('js-sha3');
const { SELECTORS } = require('../lib/selectors');

test('all selectors match keccak256 of their signature', () => {
  for (const [sel, v] of Object.entries(SELECTORS)) {
    const computed = '0x' + keccak256(v.name).slice(0, 8);
    assert.equal(computed, sel, `${v.name}: table says ${sel}, keccak says ${computed}`);
  }
});

test('table is non-empty and every kind is handled by the policy', () => {
  const kinds = new Set(Object.values(SELECTORS).map((v) => v.kind));
  for (const k of ['approval', 'approval_all', 'permit', 'multicall', 'mint', 'claim', 'transfer']) {
    assert.ok(kinds.has(k), `missing kind ${k}`);
  }
});
