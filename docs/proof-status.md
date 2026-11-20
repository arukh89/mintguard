# Proof status — Groth16 proof of verdict (official gatekeeper circuit)

## What is proven

Each MintGuard verdict is encoded as inputs to the tournament's official
Proof Gatekeeper circuit (Groth16/BN128, Circom 2.x), and a proof is
generated with `snarkjs`. The encoding is defined in
`scripts/prove-verdict.js`:

| Circuit input | MintGuard meaning |
|---|---|
| `amount` | risk score (0–100) |
| `maxTransfer` | 29 (the ALLOW ceiling) |
| `decision` | 1 iff `amount <= maxTransfer`, else 0 |
| `registeredVkHash` / `proofVkHash` | official registered vk hash (equal => verdict's claim is from the registered key) |
| `minimum` / `publicBalance` | 0 / 1 (threshold check passes) |
| `expiryBlock` / `currentBlock` | 1000000 / 1 (not expired) |
| `recipient` / `conditionRecipient` | target contract address as integer (equal) |
| `taskId` / `salt` | demo identifiers (salt is a public demo value) |

The circuit enforces that `decision` is consistent with the five
checks (vk match, threshold, expiry, recipient, amount cap). The proof
therefore proves the encoded verdict is consistent with those checks —
not that the guard's Sourcify lookup or selector decoding happened.
Those run outside the circuit; a full in-circuit guard would need a
custom circuit, which is out of scope for this season.

## Verified results (2026-11-20, this machine)

Generated with `node scripts/prove-verdict.js`:

- **ALLOW, score 0** (Meow Cards free mint): `fullProve` 885 ms,
  `groth16.verify = true`
- **BLOCK, score 85** (unlimited approval, unverified contract):
  `fullProve` 303 ms, `groth16.verify = true`

Re-verify any time, offline: `node scripts/verify-proof.js`
(also covered by the proof files below).

## Artifacts

- `circuits/gatekeeper.wasm` — official, downloaded from
  https://agentgames.zkverify.io/circuits/gatekeeper.wasm,
  sha256 `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f`
  (matches the published hash). Gitignored; re-download from the
  official `/api/circuit-info` endpoint.
- `circuits/gatekeeper_final.zkey` — official, same source,
  sha256 `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d`,
  309,750 bytes. Gitignored.
- `circuits/verification_key.json` — exported from the zkey with
  `snarkjs.zKey.exportVerificationKey`. Committed. bn128, nPublic 13.
- `circuits/proof-allow-score0.json`, `circuits/proof-block-score85.json`
  — the two verified proofs with their public signals. Committed.
- Registered vk hash (from `/api/circuit-info`):
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`

Note on the vk hash: the hex value exceeds the BN128 field prime, so
the witness calculator reduces it mod p (both copies identically —
public signals show `4836144126773920907502496244340012141761656471453348073975163706578152814510`
for both `registeredVkHash` and `proofVkHash`). Equality semantics
survive the reduction.

## What is NOT claimed

- The live `/analyze` endpoint does **not** generate a proof per
  request (proof generation is an offline step; the endpoint is
  stdlib-only by design). The live checkable claim is deterministic
  recomputation via `POST /verify` + HMAC receipt.
- The proof does not cover the Sourcify lookup or the selector
  decoding. Those are covered by the test suite and by `/verify`
  recomputation, not by the circuit.
