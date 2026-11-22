// Agent-wallet login for MintGuard — dependency-free.
//
// Flow (same challenge -> signature -> verify pattern DEEP SWARM and
// Kernel Agents use for Binance Agentic Wallet logins):
//   1. GET  /auth/challenge?address=0x...&agentId=ukhy89.ai
//      -> EIP-712 typed data (domain MintGuard, chain 56) + nonce +
//         expiry + the exact `baw sign-message` command to run.
//   2. The agent signs with `baw sign-message preview --binanceChainId 56
//      --signType EIP712 --message '<eth_signTypedData_v4 wrapper>'`
//      then `execute --requestId <id>` (user confirms first) and
//      `result --order-id <id>` for the signature. Developer Mode must
//      be enabled in the Binance App for external signing.
//   3. POST /auth/login { address, agentId, nonce, expiresAt, signature }
//      -> the server recomputes the EIP-712 digest, recovers the signer
//         with pure-JS secp256k1 ecrecover, checks the address matches,
//         checks the Agent ID registry (balanceOf > 0, best effort), and
//         issues an HMAC bearer token (24h, self-contained).
//
// The server is stateless, so there is no server-side used-nonce store:
// a challenge is valid for 5 minutes and a signature can be replayed
// inside that window to mint a fresh token. The token only gates the
// console display (and tags /analyze calls with the agent) — /analyze
// itself stays public. That limit is documented in docs/auth-notes.md.
//
// All crypto here is implemented from the spec (Keccak-f[1600],
// secp256k1, EIP-712) with BigInt. It is validated against independent
// references in test/auth.test.js (known keccak vectors + an EIP-712
// signature produced by ethers, not by this code).
'use strict';

const { randomBytes, createHmac } = require('node:crypto');
const { signReceipt, verifyReceipt } = require('./receipt');

const AGENT_ID_CHAIN_ID = 56;
const AGENT_ID_REGISTRY = '0x60b9262456de011f7d15a54cdd8c48baaa8b022f'; // SPACE ID Agent ID, ERC-721, BSC mainnet
const CHALLENGE_TTL_SECONDS = 300;
const SESSION_TTL_SECONDS = 24 * 60 * 60;
const EIP712_DOMAIN = { name: 'MintGuard', version: '1', chainId: AGENT_ID_CHAIN_ID };
const EIP712_TYPES = {
  Login: [
    { name: 'wallet', type: 'address' },
    { name: 'agentId', type: 'string' },
    { name: 'nonce', type: 'bytes32' },
    { name: 'expiresAt', type: 'uint256' },
  ],
};

// ---------------------------------------------------------------------------
// byte helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex) {
  const s = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (s.length % 2 !== 0) throw new Error('odd-length hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes) {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return '0x' + out;
}

function utf8Bytes(str) {
  return new TextEncoder().encode(str);
}

function isAddress(s) {
  return typeof s === 'string' && /^0x[0-9a-fA-F]{40}$/.test(s);
}

function normalizeAddress(s) {
  return s.toLowerCase();
}

// ---------------------------------------------------------------------------
// keccak-256 (Keccak-f[1600], rate 1088, suffix 0x01)
// ---------------------------------------------------------------------------

const KECCAK_MASK = (1n << 64n) - 1n;
const KECCAK_RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const KECCAK_ROT = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];

function keccakRotl(v, n) {
  if (n === 0) return v;
  const b = BigInt(n);
  return ((v << b) | (v >> (64n - b))) & KECCAK_MASK;
}

function keccakF(state) {
  for (let round = 0; round < 24; round++) {
    // theta
    const c = new Array(5);
    for (let x = 0; x < 5; x++) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5] ^ keccakRotl(c[(x + 1) % 5], 1);
      for (let y = 0; y < 5; y++) state[x + 5 * y] ^= d;
    }
    // rho + pi
    const b = new Array(25);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = keccakRotl(state[x + 5 * y], KECCAK_ROT[x][y]);
      }
    }
    // chi
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        state[x + 5 * y] = b[x + 5 * y] ^ ((~b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y]);
      }
    }
    // iota
    state[0] ^= KECCAK_RC[round];
  }
}

function keccak256(data) {
  const bytes = data instanceof Uint8Array ? data : utf8Bytes(String(data));
  const rate = 136; // 1088 bits
  const state = new Array(25).fill(0n);
  let off = 0;
  while (off + rate <= bytes.length) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let j = 0; j < 8; j++) lane |= BigInt(bytes[off + i * 8 + j]) << BigInt(8 * j);
      state[i] ^= lane;
    }
    keccakF(state);
    off += rate;
  }
  // final block with pad10*1, suffix 0x01
  const block = new Uint8Array(rate);
  block.set(bytes.subarray(off));
  block[bytes.length - off] ^= 0x01;
  block[rate - 1] ^= 0x80;
  for (let i = 0; i < rate / 8; i++) {
    let lane = 0n;
    for (let j = 0; j < 8; j++) lane |= BigInt(block[i * 8 + j]) << BigInt(8 * j);
    state[i] ^= lane;
  }
  keccakF(state);
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let lane = state[i];
    for (let j = 0; j < 8; j++) {
      out[i * 8 + j] = Number(lane & 0xffn);
      lane >>= 8n;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// secp256k1 (affine, BigInt) + ecrecover
// ---------------------------------------------------------------------------

const SECP_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const SECP_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP_G = {
  x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
};

function modInv(a, m) {
  let [oldR, r] = [((a % m) + m) % m, m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  return ((oldS % m) + m) % m;
}

function pointAdd(p, q) {
  if (!p) return q;
  if (!q) return p;
  if (p.x === q.x && (p.y + q.y) % SECP_P === 0n) return null; // infinity
  let m;
  if (p.x === q.x && p.y === q.y) {
    m = ((3n * p.x * p.x) * modInv(2n * p.y, SECP_P)) % SECP_P;
  } else {
    m = ((q.y - p.y) * modInv(q.x - p.x, SECP_P)) % SECP_P;
  }
  const x = (((m * m - p.x - q.x) % SECP_P) + SECP_P) % SECP_P;
  const y = (((m * (p.x - x) - p.y) % SECP_P) + SECP_P) % SECP_P;
  return { x, y };
}

function scalarMult(k, point) {
  let acc = null;
  let add = point;
  let n = k;
  while (n > 0n) {
    if (n & 1n) acc = pointAdd(acc, add);
    add = pointAdd(add, add);
    n >>= 1n;
  }
  return acc;
}

function bytesToBigInt(bytes) {
  let out = 0n;
  for (const b of bytes) out = (out << 8n) | BigInt(b);
  return out;
}

function bigIntToBytes32(n) {
  const out = new Uint8Array(32);
  let v = n;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

// Recover the signer address from a 32-byte digest and a 65-byte
// signature (r || s || v, v = 27/28). Returns the lowercase address
// or null when the signature is malformed.
function recoverAddress(digestBytes, signatureHex) {
  try {
    const sig = hexToBytes(signatureHex);
    if (sig.length !== 65) return null;
    const r = bytesToBigInt(sig.subarray(0, 32));
    const s = bytesToBigInt(sig.subarray(32, 64));
    let v = sig[64];
    if (v === 27 || v === 28) v -= 27;
    if (v !== 0 && v !== 1) return null;
    if (r <= 0n || r >= SECP_N || s <= 0n || s >= SECP_N) return null;
    const e = bytesToBigInt(digestBytes);
    // R = (r, y) with the parity given by v
    const x = r;
    const ySq = (x * x * x + 7n) % SECP_P;
    // y = ySq^((p+1)/4) mod p (p % 4 == 3)
    let y = modPow(ySq, (SECP_P + 1n) / 4n, SECP_P);
    if ((y * y) % SECP_P !== ySq) return null;
    if (Number(y & 1n) !== v) y = SECP_P - y;
    const rPoint = { x, y };
    const rInv = modInv(r, SECP_N);
    const u1 = (((-e * rInv) % SECP_N) + SECP_N) % SECP_N;
    const u2 = (s * rInv) % SECP_N;
    const q = pointAdd(scalarMult(u1, SECP_G), scalarMult(u2, rPoint));
    if (!q) return null;
    const pub = new Uint8Array(64);
    pub.set(bigIntToBytes32(q.x), 0);
    pub.set(bigIntToBytes32(q.y), 32);
    const hash = keccak256(pub);
    return bytesToHex(hash.subarray(12));
  } catch {
    return null;
  }
}

function modPow(base, exp, mod) {
  let out = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) out = (out * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return out;
}

// ---------------------------------------------------------------------------
// EIP-712 (Login typed data)
// ---------------------------------------------------------------------------

function encodeUint256(n) {
  return bigIntToBytes32(BigInt(n));
}

function encodeAddress(addr) {
  const out = new Uint8Array(32);
  out.set(hexToBytes(addr), 12);
  return out;
}

function eip712DomainSeparator() {
  const typeHash = keccak256(utf8Bytes('EIP712Domain(string name,string version,uint256 chainId)'));
  const parts = new Uint8Array(32 * 4);
  parts.set(typeHash, 0);
  parts.set(keccak256(utf8Bytes(EIP712_DOMAIN.name)), 32);
  parts.set(keccak256(utf8Bytes(EIP712_DOMAIN.version)), 64);
  parts.set(encodeUint256(EIP712_DOMAIN.chainId), 96);
  return keccak256(parts);
}

function eip712LoginStructHash(message) {
  const typeHash = keccak256(utf8Bytes('Login(address wallet,string agentId,bytes32 nonce,uint256 expiresAt)'));
  const parts = new Uint8Array(32 * 5);
  parts.set(typeHash, 0);
  parts.set(encodeAddress(message.wallet), 32);
  parts.set(keccak256(utf8Bytes(message.agentId)), 64);
  parts.set(hexToBytes(message.nonce), 96);
  parts.set(encodeUint256(message.expiresAt), 128);
  return keccak256(parts);
}

function eip712Digest(typedData) {
  const prefix = new Uint8Array([0x19, 0x01]);
  const parts = new Uint8Array(2 + 32 + 32);
  parts.set(prefix, 0);
  parts.set(eip712DomainSeparator(), 2);
  parts.set(eip712LoginStructHash(typedData.message), 34);
  return keccak256(parts);
}

// Build the exact typed data for a login challenge. Pure: same inputs
// always give the same typed data (used by the fixture generator).
function loginTypedData(address, agentId, nonce, expiresAt) {
  return {
    types: EIP712_TYPES,
    primaryType: 'Login',
    domain: { ...EIP712_DOMAIN },
    message: {
      wallet: normalizeAddress(address),
      agentId,
      nonce,
      expiresAt,
    },
  };
}

// Build a fresh challenge: random nonce, 5-minute expiry, plus the
// exact `baw sign-message` invocation that signs it.
function buildChallenge(address, agentId) {
  const nonce = bytesToHex(randomBytes(32));
  const expiresAt = Math.floor(Date.now() / 1000) + CHALLENGE_TTL_SECONDS;
  const typedData = loginTypedData(address, agentId, nonce, expiresAt);
  const bawMessage = JSON.stringify({
    method: 'eth_signTypedData_v4',
    params: [normalizeAddress(address), typedData],
  });
  const signCommand =
    'baw sign-message preview --binanceChainId 56 --signType EIP712 --message \'' +
    bawMessage +
    '\' --json';
  return { typedData, nonce, expiresAt, bawMessage, signCommand };
}

// Verify a login submission. Returns { ok, address, agentId } or
// { ok: false, error }. nowSeconds is test-only (defaults to now).
function verifyLogin(body, nowSeconds) {
  if (!body || typeof body !== 'object') return { ok: false, error: 'body must be a JSON object' };
  const { address, agentId, nonce, expiresAt, signature } = body;
  if (!isAddress(address)) return { ok: false, error: 'address must be a 0x address' };
  if (typeof agentId !== 'string' || !agentId.trim() || agentId.length > 64) {
    return { ok: false, error: 'agentId must be a non-empty string (max 64 chars)' };
  }
  if (typeof nonce !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(nonce)) {
    return { ok: false, error: 'nonce must be a 0x bytes32 value' };
  }
  if (!Number.isInteger(expiresAt)) return { ok: false, error: 'expiresAt must be an integer unix timestamp' };
  const now = nowSeconds === undefined ? Math.floor(Date.now() / 1000) : nowSeconds;
  if (expiresAt <= now) return { ok: false, error: 'challenge expired' };
  if (expiresAt > now + CHALLENGE_TTL_SECONDS + 60) {
    return { ok: false, error: 'challenge expiry too far in the future' };
  }
  if (typeof signature !== 'string' || !/^0x[0-9a-fA-F]{130}$/.test(signature)) {
    return { ok: false, error: 'signature must be a 0x 65-byte signature' };
  }
  const typedData = loginTypedData(address, agentId.trim(), nonce, expiresAt);
  const digest = eip712Digest(typedData);
  const recovered = recoverAddress(digest, signature);
  if (!recovered) return { ok: false, error: 'signature could not be recovered' };
  if (recovered !== normalizeAddress(address)) {
    return { ok: false, error: 'signature does not match the claimed address' };
  }
  return { ok: true, address: normalizeAddress(address), agentId: agentId.trim() };
}

// ---------------------------------------------------------------------------
// Agent ID registry check (best effort): balanceOf(address) > 0 proves
// the address holds an Agent ID. Returns { holding, checked }.
// ---------------------------------------------------------------------------

const BSC_RPCS = [
  'https://bsc-dataseed.binance.org/',
  'https://bsc-dataseed1.defibit.io/',
  'https://binance.llamarpc.com/',
];

async function checkAgentIdHolding(address, fetchFn) {
  const fetchImpl = fetchFn || fetch;
  const data = '0x70a08231' + address.slice(2).padStart(64, '0');
  const payload = {
    jsonrpc: '2.0',
    id: 1,
    method: 'eth_call',
    params: [{ to: AGENT_ID_REGISTRY, data }, 'latest'],
  };
  for (const url of BSC_RPCS) {
    try {
      const res = await fetchImpl(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(5000),
      });
      const j = await res.json();
      if (typeof j.result === 'string' && /^0x[0-9a-fA-F]+$/.test(j.result)) {
        return { holding: BigInt(j.result) > 0n, checked: true };
      }
    } catch {
      // try the next RPC
    }
  }
  return { holding: false, checked: false };
}

// ---------------------------------------------------------------------------
// Session tokens: self-contained HMAC tokens (same secret as receipts).
// token = base64url(payloadJson) + '.' + HMAC(payload)
// ---------------------------------------------------------------------------

function b64urlEncode(str) {
  return Buffer.from(str, 'utf8').toString('base64url');
}

function b64urlDecode(s) {
  return Buffer.from(s, 'base64url').toString('utf8');
}

function issueSession(address, agentId) {
  const payload = {
    v: 1,
    kind: 'mintguard-session',
    address: normalizeAddress(address),
    agentId,
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  };
  const sig = signReceipt(payload);
  return b64urlEncode(JSON.stringify(payload)) + '.' + sig;
}

function verifySession(token) {
  try {
    if (typeof token !== 'string') return null;
    const dot = token.lastIndexOf('.');
    if (dot <= 0) return null;
    const payload = JSON.parse(b64urlDecode(token.slice(0, dot)));
    if (!payload || payload.v !== 1 || payload.kind !== 'mintguard-session') return null;
    if (!isAddress(payload.address) || typeof payload.agentId !== 'string') return null;
    if (!Number.isInteger(payload.exp) || payload.exp <= Math.floor(Date.now() / 1000)) return null;
    if (!verifyReceipt(payload, token.slice(dot + 1))) return null;
    return { address: payload.address, agentId: payload.agentId, exp: payload.exp };
  } catch {
    return null;
  }
}

function bearerToken(headers) {
  if (!headers || typeof headers !== 'object') return null;
  const auth = headers.authorization || headers.Authorization;
  if (typeof auth !== 'string') return null;
  const m = auth.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

module.exports = {
  AGENT_ID_CHAIN_ID,
  AGENT_ID_REGISTRY,
  CHALLENGE_TTL_SECONDS,
  SESSION_TTL_SECONDS,
  EIP712_DOMAIN,
  hexToBytes,
  bytesToHex,
  utf8Bytes,
  isAddress,
  normalizeAddress,
  keccak256,
  recoverAddress,
  eip712Digest,
  loginTypedData,
  buildChallenge,
  verifyLogin,
  checkAgentIdHolding,
  issueSession,
  verifySession,
  bearerToken,
  _hmacForTests: createHmac,
};
