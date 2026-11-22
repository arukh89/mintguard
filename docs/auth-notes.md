# Agent wallet login — notes

MintGuard's demo console offers an optional login with the Binance
Agentic Wallet (Agent ID). Login is **not** required to use the guard:
`/analyze`, `/verify`, `/health`, and `/policy` stay public and
unchanged. A logged-in session only tags `/analyze` responses with
`signedInAs` and shows the agent in the console.

## Flow

1. `GET /auth/challenge?address=0x...&agentId=ukhy89.ai` returns an
   EIP-712 typed-data challenge (`MintGuard`, version `1`, chain 56),
   a random `bytes32` nonce, a 5-minute expiry, and the exact
   `baw sign-message` command that signs it.
2. The agent signs with the Agentic Wallet:
   `baw sign-message preview --binanceChainId 56 --signType EIP712
   --message '<eth_signTypedData_v4 wrapper>' --json`, confirms the
   preview, then `execute --requestId <id>`, then
   `result --order-id <id>` for the signature. Developer Mode must be
   enabled in the Binance App (Agentic Wallet → Settings) for external
   signing.
3. `POST /auth/login { address, agentId, nonce, expiresAt, signature }`
   recomputes the EIP-712 digest, recovers the signer with pure-JS
   secp256k1 `ecrecover` (no dependencies), checks the recovered
   address matches, checks the Agent ID registry
   (`0x60b9262456de011f7d15a54cdd8c48baaa8b022f`, SPACE ID Agent ID,
   `balanceOf(address) > 0`, best effort), and issues a self-contained
   HMAC bearer token valid 24 hours.
4. `GET /auth/me` with `Authorization: Bearer <token>` returns the
   session's address and Agent ID.

## Honest limits

- **Stateless server, no used-nonce store.** A challenge is valid for
  5 minutes; a signature can be replayed inside that window to mint a
  fresh token. The token only gates the console display and tags
  analyses — it does not protect funds or the guard itself.
- **Signature proves control of the address; the Agent ID name is
  client-claimed.** The registry check proves the address *holds an*
  Agent ID (`balanceOf > 0`), not that the claimed name is the exact
  token the address holds. Exact name↔address binding is verified
  out-of-band for the operator's wallet.
- **Registry check is best effort.** If all public BSC RPCs fail, the
  login still succeeds on the signature and the response says the
  holding check is unverified (`agentIdHoldingChecked: false`).
- **EIP-712 only.** `baw sign-message` documents `--signType EIP712`;
  `PERSONAL_SIGN` is not used.
- **The `baw` CLI session is flaky.** It has gone `NOT_LOGGED_IN`
  more than once despite a never-expired setting (last seen 22 Nov
  07:44 WIB). Signing needs a live session: `baw auth signin` + QR
  approval in the Binance App, and Developer Mode on.
- **No private key or seed is ever involved.** Signing happens inside
  the Agentic Wallet (MPC); the server only ever sees the signature.

## Verification

- `test/auth.test.js` (10 tests): keccak-256 known vectors, EIP-712
  digest equal to ethers' `TypedDataEncoder.hash`, `ecrecover`
  recovering the ethers signer, login accept/reject cases, session
  round-trip/tamper/expiry, registry parsing with a stubbed fetch.
  The fixture `test/fixtures/eip712-login.json` was signed by ethers
  with a throwaway test key whose private key was never saved.
- Local end-to-end (`/tmp/verify-auth-e2e.js`, not shipped): fresh
  challenge → sign with a fresh throwaway key → login → `/auth/me`
  → `/analyze` tagged `signedInAs`; negatives (tampered signature,
  expired challenge, bad token) all rejected.
