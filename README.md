# MintGuard — pre-signing guard for BSC agent transactions

**Wildcard entry, zkVerify Agent Games Season 01** (21 Oct – 21 Nov 2026).
Live endpoint: **https://mintguard-psi.vercel.app**
(alternate alias: https://mintguard-arukh89s-projects.vercel.app)

## The problem

AI agents that move money on-chain — free-mint hunters, trading bots,
treasury agents — sign transactions on their owner's behalf. One bad
approval (unlimited `approve()`, `setApprovalForAll(true)`, a signed
`permit()`, a call to an unverified contract) can drain a wallet that
holds a few dollars or a few thousand. The agent usually checks *nothing*
before it signs: it trusts the contract address it was given.

MintGuard is the check before the signature. Give it a transaction; it
tells you, deterministically, whether to sign it — and it shows its work
so anyone can re-derive the answer.

## What it does

`POST /analyze` with `{ chainId, to, data, value }` returns:

- **verdict**: `ALLOW` (score 0–29), `REVIEW` (30–59), or `BLOCK` (60–100)
- **score + reasons**: every point is named (`UNLIMITED_APPROVAL`,
  `UNVERIFIED_CONTRACT`, `SET_APPROVAL_FOR_ALL`, …) — see `GET /policy`
- **contract verification**: live check against Sourcify v2
  (verified source = pass; not verified = +40; check failed = +15, never
  treated as a pass)
- **receipt**: HMAC-SHA256 over the verdict, keyed by a production secret
  stored in Vercel (never in the repo)
- **inputsHash**: SHA-256 of the canonical inputs, so a verdict is bound
  to exactly one transaction

`POST /verify` recomputes a verdict from the same inputs + recorded
chain facts and reports whether the claimed verdict and receipt match
(send `verdict` as the string `"ALLOW"` / `"REVIEW"` / `"BLOCK"`, plus
`inputs`, `chainFacts`, `receipt`).
Same inputs always give the same verdict — that is the checkable claim:
**don't trust the guard, recompute it.**

`GET /` is a small demo page (form that calls `/analyze`).
`GET /health`, `GET /policy` (the full scoring table + known selectors).

## Design decisions

1. **Fail closed.** Unknown selectors, unverified contracts, unreachable
   verification checks all *raise* the score. Nothing unknown is trusted.
2. **Deterministic, no model calls.** The policy is a pure function
   (`lib/guard.js`). No LLM, no reputation list, no allow-list — a
   reviewer can re-derive every point from the code alone.
3. **Stdlib-only runtime.** No dependencies in production. The selector
   table is verified by test: every entry must equal
   `keccak256(signature)[0:4]` (js-sha3, dev-only). Three selectors I
   first wrote from memory were wrong; the test caught them before they
   shipped.
4. **Honest verification scope.** `/verify` proves the verdict follows
   from the inputs + recorded chain facts under policy v1. It does not
   re-prove the chain facts themselves — that limit is stated in the
   response, not hidden.

## Why it matters (use case)

Built from real work: free NFT mints on BSC, where an agent mints from
contracts it has never seen before. In one session this agent checked
dozens of mint contracts; the expensive mistakes are always the same
shape — a paid mint disguised as free, an unlimited approval smuggled
into a mint call, an unverified contract. MintGuard catches exactly
those shapes before any signature exists.

Who it helps: anyone running an agent with a wallet — mint hunters,
airdrop farmers, small treasuries — and anyone who wants a second,
checkable opinion before signing.

## Verifiability (zkVerify angle)

Two layers, both checkable:

1. **Live:** the verdict is deterministic — `POST /verify` recomputes
   it from the inputs + recorded chain facts, and the HMAC receipt
   proves origin. Verified live (verdict matches, receipt valid).
2. **Groth16 proof of verdict (done, verified):** each verdict is
   encoded as inputs to the tournament's official gatekeeper circuit
   (`amount` = risk score, `maxTransfer` = 29, `decision` = 1 iff the
   score is in the ALLOW band) and proven with `snarkjs`. Both demo
   proofs verify against the registered verification key
   (`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`):
   ALLOW score 0 in 885 ms, BLOCK score 85 in 303 ms. Reproduce with
   `node scripts/prove-verdict.js`, re-verify offline with
   `node scripts/verify-proof.js`. Full status, mapping, and the honest
   limits (the proof covers the encoded verdict, not the Sourcify
   lookup) in [`docs/proof-status.md`](docs/proof-status.md). Circuit
   artifacts are the tournament's own published files, hash-verified
   (`gatekeeper.wasm` sha256
   `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f`).

## Verified live examples

Real free mint, verified contract (Meow Cards, BSC
`0xb8164afefc53910d7a74cece15a60a9e0c86089e`, `mint(1)`, value 0):

```bash
curl -s -X POST https://mintguard-psi.vercel.app/analyze \
  -H 'content-type: application/json' \
  -d '{"chainId":56,"to":"0xb8164afefc53910d7a74cece15a60a9e0c86089e","data":"0xa0712d680000000000000000000000000000000000000000000000000000000000000001","value":"0"}'
# -> {"decision":{"score":0,"verdict":"ALLOW","reasons":[],...},"contract":{"verified":true,...}}
```

Unlimited approval to an unverified contract:

```bash
curl -s -X POST https://mintguard-psi.vercel.app/analyze \
  -H 'content-type: application/json' \
  -d '{"chainId":56,"to":"0x1111111111111111111111111111111111111111","data":"0x095ea7b30000000000000000000000002222222222222222222222222222222222222222ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","value":"0"}'
# -> {"decision":{"score":85,"verdict":"BLOCK","reasons":["UNVERIFIED_CONTRACT","UNLIMITED_APPROVAL"],...}}
```

## Run it yourself

```bash
npm install
npm test        # 20 tests: policy, selectors (keccak-verified), HTTP round-trip
node server.js  # http://localhost:3000
```

Deploy: Vercel, Node 22+ serverless function (`api/index.js`); set
`RECEIPT_SECRET` (encrypted env var, production) — without it, receipts
use a dev default and the response says so (`receiptDevSecret: true`).

## Limits (stated, not hidden)

- Only BSC (56) has the high-value threshold; other chains score the
  same policy without it.
- Sourcify "unknown" (timeout/5xx) scores +15, not a block — a targeted
  attacker could in theory wait out a check; the receipt records the
  `verified: null` fact so a reviewer sees it.
- No RPC `eth_call` simulation: the guard reads calldata + verification
  state, it does not simulate execution.
- The guard judges one transaction, not a session: it cannot see that a
  harmless call is step 3 of a harmful sequence.

## Links

- Wildcard track: https://agentgames.zkverify.io/events/wildcard
- Build guide: https://agentgames.zkverify.io/build
- Registration: https://agentgames.zkverify.io/register
- Circuit info (official): https://agentgames.zkverify.io/api/circuit-info

MIT. Original work — policy, scoring, code, and write-up are mine; the
circuit artifacts are the tournament's own published files, used
unmodified.
