# Wildcard submission pack — MintGuard
# Copy these fields into the submission form on the Agent Games dashboard
# (https://agentgames.zkverify.io/ — after registering). Nothing here
# contains private data; the whitelist wallet below is the public one
# already used for whitelist/giveaway tasks.

TRACK: Wildcard
AGENT NAME: MintGuard
HANDLE: @rukhyatahmad (platform handle = X handle, permanent, cannot be changed; GitHub: arukh89)

AGENT LINK (public repo):
  https://github.com/arukh89/mintguard
  (repo to be created from ~/workspace/hacklist/zkverify-agent-games/;
   README carries the full write-up, demo commands, and limits)

PUBLIC ENDPOINT:
  https://mintguard-psi.vercel.app
  Alternate alias: https://mintguard-arukh89s-projects.vercel.app
  - GET  /        demo page (form that calls /analyze)
  - GET  /health  liveness + policy version
  - GET  /policy  full scoring table + known selectors
  - POST /analyze { chainId, to, data, value } -> verdict + receipt
  - POST /verify  { inputs, chainFacts, verdict, receipt } -> recomputation
    (verdict = the string 'ALLOW' / 'REVIEW' / 'BLOCK')

USE CASE:
  AI agents that hold wallets sign transactions on their owner's behalf —
  free-mint hunters, trading bots, small treasuries. One bad approval
  (unlimited approve, setApprovalForAll, a signed permit, a call to an
  unverified contract) can drain the wallet. MintGuard is the check
  before the signature: it decodes the calldata, checks the target
  contract's source verification live on Sourcify, and returns a
  deterministic ALLOW / REVIEW / BLOCK verdict with named reasons and a
  risk score. Built from real free-mint work on BSC, where the expensive
  mistakes are always the same shapes: a paid mint disguised as free, an
  unlimited approval smuggled into a mint call, an unverified contract.

BUILD CONTEXT:
  Node.js, stdlib-only runtime (no production dependencies), deployed as
  a Vercel serverless function. The policy is a pure function
  (lib/guard.js): fail-closed scoring (unknown = higher score, never
  trusted), deterministic (same inputs => same verdict), no model calls,
  no allow-lists. The selector table is verified by test — every entry
  must equal keccak256(signature)[0:4]; three entries first written from
  memory were wrong and the test caught them. Sourcify v2 is checked live
  per request (5s timeout; failure scores +15 and is recorded, never
  treated as verified). Verdicts carry an HMAC-SHA256 receipt keyed by a
  production secret in Vercel, and POST /verify recomputes any verdict so
  a reviewer never has to trust a screenshot.

ZKVERIFY (optional):
  The verdict is a checkable claim today via deterministic recomputation
  + HMAC receipt (see /verify). Groth16 proof layer against the
  tournament's official gatekeeper circuit is DONE and VERIFIED locally
  (2026-11-20): ALLOW score 0 proves in 885 ms, groth16.verify=true;
  BLOCK score 85 proves in 303 ms, groth16.verify=true; registered
  verification key 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0.
  Proofs + public signals in circuits/proof-allow-score0.json and
  circuits/proof-block-score85.json; reproduce with
  `node scripts/prove-verdict.js`, re-verify offline with
  `node scripts/verify-proof.js`. Honest limit (docs/proof-status.md):
  the proof covers the encoded verdict, not the Sourcify lookup itself.

WALLET (for prizes, if asked):
  0x9A199248dF590bFBF26a02935E1aE65ab504E034

DEADLINE: 21 Nov 2026 22:00 UTC = 22 Nov 2026 05:00 WIB
JUDGING: 23-30 Nov 2026, manual review. Winners announced first week of Dec.
PRIZE (Wildcard): 100,000 VFY total — 1st 50,000 / 2nd 30,000 / 3rd 20,000.
