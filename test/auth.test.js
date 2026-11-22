// Auth tests: keccak-256 vectors, EIP-712 digest + ecrecover against an
// ethers-signed fixture (the signature was produced by ethers, not by
// this code), login verification incl. negatives, session tokens, and
// the Agent ID registry check (fetch stubbed).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  keccak256,
  bytesToHex,
  utf8Bytes,
  recoverAddress,
  eip712Digest,
  loginTypedData,
  buildChallenge,
  verifyLogin,
  checkAgentIdHolding,
  issueSession,
  verifySession,
  AGENT_ID_REGISTRY,
} = require('../lib/auth');
const { signReceipt } = require('../lib/receipt');
const fixture = require('./fixtures/eip712-login.json');

const NOW = fixture.expiresAt - 1; // just inside the challenge window

test('keccak-256 known vectors', () => {
  assert.equal(bytesToHex(keccak256(utf8Bytes(''))), '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
  assert.equal(bytesToHex(keccak256(utf8Bytes('abc'))), '0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45');
  assert.equal(
    bytesToHex(keccak256(utf8Bytes('The quick brown fox jumps over the lazy dog'))),
    '0x4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15'
  );
});

test('EIP-712 digest matches ethers', () => {
  assert.equal(bytesToHex(eip712Digest(fixture.typedData)), fixture.ethersDigest.toLowerCase());
});

test('ecrecover recovers the ethers signer', () => {
  const digest = eip712Digest(fixture.typedData);
  assert.equal(recoverAddress(digest, fixture.signature), fixture.address.toLowerCase());
});

// Note: no OpenSSL cross-check here on purpose. Node's
// crypto.sign/verify with a null algorithm hashes the input first
// (verified: a Node-made signature over a digest does not recover with
// ecrecover), so it cannot verify a raw-digest ECDSA signature. The
// independent validation is the ethers-signed fixture itself: ethers
// produced the digest and the signature, this code verifies both.
test('ecrecover is sensitive to v and rejects garbage', () => {
  const digest = eip712Digest(fixture.typedData);
  const good = fixture.signature;
  assert.equal(recoverAddress(digest, good), fixture.address.toLowerCase());
  const flippedV = good.slice(0, -2) + (good.endsWith('1c') ? '1b' : '1c');
  assert.notEqual(recoverAddress(digest, flippedV), fixture.address.toLowerCase());
  assert.equal(recoverAddress(digest, '0x' + '00'.repeat(65)), null);
  assert.equal(recoverAddress(digest, '0x1234'), null);
});

test('verifyLogin accepts the fixture login', () => {
  const out = verifyLogin(
    {
      address: fixture.address,
      agentId: fixture.agentId,
      nonce: fixture.nonce,
      expiresAt: fixture.expiresAt,
      signature: fixture.signature,
    },
    NOW
  );
  assert.equal(out.ok, true);
  assert.equal(out.address, fixture.address.toLowerCase());
  assert.equal(out.agentId, fixture.agentId);
});

test('verifyLogin rejects tampered agentId, bad signature, wrong address, expired challenge', () => {
  const good = {
    address: fixture.address,
    agentId: fixture.agentId,
    nonce: fixture.nonce,
    expiresAt: fixture.expiresAt,
    signature: fixture.signature,
  };
  assert.equal(verifyLogin({ ...good, agentId: 'someone-else.ai' }, NOW).ok, false);
  const badSig = fixture.signature.slice(0, -2) + (fixture.signature.endsWith('1c') ? '1b' : '1c');
  assert.equal(verifyLogin({ ...good, signature: badSig }, NOW).ok, false);
  assert.equal(verifyLogin({ ...good, address: '0x2222222222222222222222222222222222222222' }, NOW).ok, false);
  assert.equal(verifyLogin(good, fixture.expiresAt + 1).ok, false);
  assert.equal(verifyLogin(good, fixture.expiresAt + 3600).ok, false);
});

test('buildChallenge shape', () => {
  const c = buildChallenge('0x8111C63E9226CE5D4C47b3EF967B88dB0431F1AB', 'ukhy89.ai');
  assert.equal(c.typedData.domain.name, 'MintGuard');
  assert.equal(c.typedData.domain.chainId, 56);
  assert.equal(c.typedData.primaryType, 'Login');
  assert.equal(c.typedData.message.wallet, '0x8111c63e9226ce5d4c47b3ef967b88db0431f1ab');
  assert.equal(c.typedData.message.agentId, 'ukhy89.ai');
  assert.match(c.nonce, /^0x[0-9a-f]{64}$/);
  assert.ok(c.expiresAt > Math.floor(Date.now() / 1000) + 240);
  assert.match(c.signCommand, /baw sign-message preview --binanceChainId 56 --signType EIP712/);
  assert.match(c.signCommand, /eth_signTypedData_v4/);
  assert.ok(c.bawMessage.includes(c.nonce));
});

test('session token round-trip, tamper rejection, expiry rejection', () => {
  const token = issueSession(fixture.address, fixture.agentId);
  const back = verifySession(token);
  assert.equal(back.address, fixture.address.toLowerCase());
  assert.equal(back.agentId, fixture.agentId);
  assert.ok(back.exp > Math.floor(Date.now() / 1000));
  // tampered payload
  const tampered = token.slice(0, 10) + 'AAAA' + token.slice(14);
  assert.equal(verifySession(tampered), null);
  assert.equal(verifySession('not-a-token'), null);
  // expired token (signed with the real secret, past exp)
  const payload = { v: 1, kind: 'mintguard-session', address: fixture.address.toLowerCase(), agentId: fixture.agentId, exp: 1000 };
  const expired = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url') + '.' + signReceipt(payload);
  assert.equal(verifySession(expired), null);
});

test('checkAgentIdHolding parses balanceOf via RPC (stubbed)', async () => {
  const stub = async (url, opts) => {
    const body = JSON.parse(opts.body);
    assert.equal(body.method, 'eth_call');
    assert.equal(body.params[0].to, AGENT_ID_REGISTRY);
    assert.match(body.params[0].data, /^0x70a08231/);
    return { json: async () => ({ result: '0x0000000000000000000000000000000000000000000000000000000000000001' }) };
  };
  assert.deepEqual(await checkAgentIdHolding(fixture.address, stub), { holding: true, checked: true });
  const zero = async () => ({ json: async () => ({ result: '0x0' }) });
  assert.deepEqual(await checkAgentIdHolding(fixture.address, zero), { holding: false, checked: true });
  const failing = async () => { throw new Error('network down'); };
  assert.deepEqual(await checkAgentIdHolding(fixture.address, failing), { holding: false, checked: false });
});

test('loginTypedData is deterministic', () => {
  const a = loginTypedData(fixture.address, fixture.agentId, fixture.nonce, fixture.expiresAt);
  const b = loginTypedData(fixture.address, fixture.agentId, fixture.nonce, fixture.expiresAt);
  assert.deepEqual(a, b);
  assert.deepEqual(a, fixture.typedData);
});
