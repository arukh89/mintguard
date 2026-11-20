# Before I let my agent sign anything, I make it prove the verdict — building MintGuard for zkVerify Agent Games

#AgentGames

*An honest build log: a pre-signing guard for BSC agent transactions,
built and deployed in one day for the Wildcard track. Every number below
comes from runs I actually did. Where something is still open, I say so.*

## The problem in one sentence

My AI agent holds a wallet and signs transactions for me — free NFT
mints on BSC, mostly — and until this week it checked *nothing* before
signing. One unlimited `approve()`, one `setApprovalForAll(true)`, one
call to an unverified contract, and the wallet is empty.

So I built the check that runs before the signature: **MintGuard**.
Live at https://mintguard-psi.vercel.app. Public repo:
https://github.com/arukh89/mintguard (being published with this article).

## What it does

Send it a transaction — `POST /analyze` with `{ chainId, to, data, value }` —
and it answers `ALLOW`, `REVIEW`, or `BLOCK`, with a risk score and named
reasons. Two real calls from the live endpoint:

**A real free mint — ALLOW, score 0.** Meow Cards on BSC
(`0xb8164afefc53910d7a74cece15a60a9e0c86089e`), `mint(1)`, value 0.
The contract is source-verified on Sourcify, the calldata is a known
mint selector, no value moves. Nothing to object to.

**An unlimited approval to an unverified contract — BLOCK, score 85.**
`approve(spender, 2^256-1)` to `0x1111…1111`: +40 for the unverified
contract, +45 for the unlimited approval. That is the shape that drains
wallets, and the guard names both halves of it.

## How it decides (the whole policy fits in one file)

The policy is a pure function — `lib/guard.js`, no model calls, no
reputation lists, no allow-lists. Points add up; 0–29 ALLOW, 30–59
REVIEW, 60+ BLOCK:

| Rule | Points |
|---|---|
| Unverified contract (Sourcify) | +40 |
| Verification check failed / timed out | +15 (never treated as a pass) |
| Unlimited approval (`>= 2^255`) | +45 |
| Any approval above zero | +10 |
| `setApprovalForAll(true)` | +40 |
| `permit()` (signed off-chain approval) | +25 |
| `multicall()` (hides the real calls) | +20 |
| Unknown calldata selector | +25 |
| Mint/claim carrying value | +20 |
| Value above 0.1 BNB on BSC | +15 |

Three design rules, and I wrote them down before I wrote code:

1. **Fail closed.** Anything unknown raises the score. Unknown is never
   silently trusted.
2. **Deterministic.** Same inputs, same verdict, every time. That is the
   checkable claim: `POST /verify` recomputes any verdict from the
   inputs and the recorded chain facts, and tells you whether the claimed
   verdict and the HMAC receipt match. I verified the round-trip live:
   verdict matches, receipt valid.
3. **Honest scope.** `/verify` proves the verdict follows from the
   inputs under this policy. It does *not* re-prove the chain facts
   themselves — and the response says that in plain text.

## The bug the tests caught before users did

I wrote the selector table from memory. Three of fifteen entries were
wrong: `safeMint(address,uint256)`, `safeMint(address)`, and `claim()`
all had incorrect 4-byte selectors. A wrong selector means the guard
misreads the call — the exact failure it exists to prevent.

The test suite recomputes every selector as `keccak256(signature)[0:4]`
and asserts it equals the table. It failed on the first run, I fixed the
three entries from the computed values, and it has passed since — 20
tests, all green, including the full `/analyze` → `/verify` round-trip
with a stubbed Sourcify. The runtime itself is stdlib-only; no
dependencies ship in production.

## Deployment notes (the unglamorous half)

Vercel serverless, Node. The first deploy attempt failed with
`missing_project_settings` (new projects need `projectSettings` in the
payload — `{"framework": null}` fixed it). Receipts are HMAC-SHA256
keyed by a secret stored as an encrypted Vercel env var; without it the
endpoint falls back to a dev default and *says so* in the response
(`receiptDevSecret: true`). After setting the real secret I redeployed
and confirmed live: `receiptDevSecret: false`.

One honest loose end: in the first minute after the first deploy, two
`POST /analyze` calls returned empty after ~30s while `GET /health`
worked. Every call since — a dozen across the session — answered in
0.5–0.7s with correct verdicts. I could not reproduce it, so I report
it instead of pretending it never happened.

## The zkVerify half — done, with receipts

The verdict is a checkable claim today (deterministic recomputation +
signed receipt). And the Groth16 layer works: I encoded two real
verdicts as inputs to the tournament's official gatekeeper circuit —
`amount` is the risk score, `maxTransfer` is 29 (the ALLOW ceiling),
`decision` is 1 exactly when the score is in the ALLOW band — and
generated proofs with `snarkjs` against the official circuit files
(`gatekeeper.wasm` sha256 matches the published hash). Both verify
against the registered verification key: ALLOW score 0 in 885 ms, BLOCK
score 85 in 303 ms. The proof files and a one-command re-verifier live
in the repo (`node scripts/verify-proof.js`).

One honest limit: the proof covers the *encoded verdict*, not the
guard's Sourcify lookup or selector decoding — those happen outside
the circuit. A full in-circuit guard would need a custom circuit.
The proof turns "the agent says it checked" into "here is the check,
verify it yourself" for the part that fits in the circuit. That is the
whole idea of the Agent Games: don't trust the agent, verify the
gatekeeper.

## Limits, stated not hidden

- Only BSC has the high-value threshold; other chains score the same
  policy without it.
- A Sourcify timeout scores +15, not a block — and the receipt records
  `verified: null`, so a reviewer sees the gap.
- No `eth_call` simulation: the guard reads calldata and verification
  state; it does not simulate execution.
- It judges one transaction, not a session: it cannot see that a
  harmless call is step 3 of a harmful sequence.

## Try it

```bash
curl -s -X POST https://mintguard-psi.vercel.app/analyze \
  -H 'content-type: application/json' \
  -d '{"chainId":56,"to":"0xb8164afefc53910d7a74cece15a60a9e0c86089e","data":"0xa0712d680000000000000000000000000000000000000000000000000000000000000001","value":"0"}'
```

Wildcard submission goes in through the Agent Games dashboard before
21 Nov 2026, 22:00 UTC. Judging is 23–30 Nov.

---
*Draft status: ready to publish. Post on dev.to with the `#AgentGames`
tag; if cross-posted to X, also tag @ZKVProtocol.*
