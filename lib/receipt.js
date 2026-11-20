// Signed receipts: HMAC-SHA256 over the canonical verdict payload.
// The receipt lets anyone confirm a verdict came from this agent's policy
// version without trusting a screenshot. It proves origin, not truth —
// truth is checked by recomputation via POST /verify.
//
// Secret: env RECEIPT_SECRET. If unset, a clearly-marked dev default is
// used and the response says so (receipts under the dev default prove
// nothing — set the secret in production).
'use strict';

const { createHmac } = require('node:crypto');

const DEV_SECRET = 'mintguard-dev-secret-NOT-FOR-PRODUCTION';

function receiptSecret() {
  return process.env.RECEIPT_SECRET || DEV_SECRET;
}
function isDevSecret() {
  return !process.env.RECEIPT_SECRET;
}

function signReceipt(payload) {
  const body = JSON.stringify(payload);
  return createHmac('sha256', receiptSecret()).update(body).digest('hex');
}

function verifyReceipt(payload, receipt) {
  if (typeof receipt !== 'string') return false;
  const expected = signReceipt(payload);
  if (receipt.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ receipt.charCodeAt(i);
  return diff === 0;
}

module.exports = { signReceipt, verifyReceipt, isDevSecret, DEV_SECRET };
