// Re-verify the committed Groth16 proofs against the exported
// verification key. No network, no secrets.
// Run: node scripts/verify-proof.js
'use strict';

const snarkjs = require('snarkjs');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');

const DIR = join(__dirname, '..', 'circuits');

(async () => {
  const vk = JSON.parse(readFileSync(join(DIR, 'verification_key.json'), 'utf8'));
  let allOk = true;
  for (const name of ['proof-allow-score0.json', 'proof-block-score85.json']) {
    const { proof, publicSignals } = JSON.parse(readFileSync(join(DIR, name), 'utf8'));
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    console.log(`${name}: groth16.verify=${ok}`);
    allOk = allOk && ok;
  }
  console.log(`RESULT all=${allOk}`);
  process.exit(allOk ? 0 : 1);
})().catch((e) => { console.error('ERR', e && e.message ? e.message : e); process.exit(2); });
