// Proof-of-verdict experiment: Groth16 proof of a MintGuard verdict
// against the tournament's official gatekeeper circuit.
//
// Mapping (MintGuard's own design — the circuit only enforces the
// arithmetic; what the numbers MEAN is this file's contract):
//   amount       = risk score (0-100)
//   maxTransfer  = 29 (the ALLOW ceiling: score <= 29)
//   decision     = 1 iff amount <= maxTransfer, else 0
//   registeredVkHash / proofVkHash = official registered vk hash
//     (equal => the verdict's "proof" is from the registered key)
//   minimum = 0, publicBalance = 1        (threshold check passes)
//   expiryBlock = 1000000, currentBlock 1 (not expired)
//   recipient = conditionRecipient = target contract address as int
//   taskId / salt = demo identifiers (salt is private)
//
// What the proof proves: that the encoded verdict is consistent with
// the circuit's checks (vk match, threshold, expiry, recipient, and
// amount<=maxTransfer iff decision=1). What it does NOT prove: the
// guard's Sourcify lookup or selector decoding — those happen outside
// the circuit. A full in-circuit guard would need a custom circuit.
// Run: node scripts/prove-verdict.js
'use strict';

const snarkjs = require('snarkjs');
const { readFileSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');

const DIR = join(__dirname, '..', 'circuits');
const VK_HASH = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const SALT = '12345678901234567890';

function inputsFor({ address, riskScore }) {
  const decision = riskScore <= 29 ? '1' : '0';
  return {
    registeredVkHash: BigInt(VK_HASH).toString(),
    proofVkHash: BigInt(VK_HASH).toString(),
    minimum: '0',
    publicBalance: '1',
    expiryBlock: '1000000',
    currentBlock: '1',
    recipient: BigInt(address).toString(),
    conditionRecipient: BigInt(address).toString(),
    amount: String(riskScore),
    maxTransfer: '29',
    decision,
    taskId: '1',
    salt: SALT,
  };
}

async function proveOne(label, spec) {
  const input = inputsFor(spec);
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    join(DIR, 'gatekeeper.wasm'),
    join(DIR, 'gatekeeper_final.zkey'),
  );
  const proveMs = Date.now() - t0;
  const vk = JSON.parse(readFileSync(join(DIR, 'verification_key.json'), 'utf8'));
  const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
  console.log(`${label}: fullProve ${proveMs}ms, groth16.verify=${ok}`);
  console.log(`  publicSignals: ${JSON.stringify(publicSignals)}`);
  console.log(`  proof.pi_a[0..1]: ${proof.pi_a.slice(0, 2).join(', ')}`);
  writeFileSync(join(DIR, `proof-${label}.json`), JSON.stringify({ input, proof, publicSignals, verified: ok }, null, 2));
  return ok;
}

(async () => {
  const allow = await proveOne('allow-score0', {
    address: '0xb8164afefc53910d7a74cece15a60a9e0c86089e', riskScore: 0,
  });
  const block = await proveOne('block-score85', {
    address: '0x1111111111111111111111111111111111111111', riskScore: 85,
  });
  console.log(`RESULT allow=${allow} block=${block}`);
  process.exit(allow && block ? 0 : 1);
})().catch((e) => { console.error('ERR', e && e.message ? e.message : e); process.exit(2); });
