// MintGuard — selector table.
//
// Every entry is verified by test/selectors.test.js, which recomputes each
// 4-byte selector as keccak256(signature)[0:4] (js-sha3, dev-only) and
// asserts it equals the value below. The runtime is stdlib-only; no
// keccak code ships in the server path.
//
// Only selectors the tests confirm are listed here. When in doubt a
// selector is left OUT and the call is classified UNKNOWN_SELECTOR (+25),
// which is the fail-closed choice: unknown code paths raise the score
// instead of being silently trusted.
'use strict';

const SELECTORS = {
  // ERC-20
  '0x095ea7b3': { name: 'approve(address,uint256)', kind: 'approval' },
  '0xa9059cbb': { name: 'transfer(address,uint256)', kind: 'transfer' },
  '0x23b872dd': { name: 'transferFrom(address,address,uint256)', kind: 'transfer' },
  // ERC-721 / ERC-1155 approvals
  '0xa22cb465': { name: 'setApprovalForAll(address,bool)', kind: 'approval_all' },
  '0xd505accf': { name: 'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)', kind: 'permit' },
  // Batching (opaque: hides the real calls)
  '0xac9650d8': { name: 'multicall(bytes[])', kind: 'multicall' },
  '0x5ae401dc': { name: 'multicall(uint256,bytes[])', kind: 'multicall' },
  // Common free-mint entry points
  '0xa0712d68': { name: 'mint(uint256)', kind: 'mint' },
  '0x40c10f19': { name: 'mint(address,uint256)', kind: 'mint' },
  '0x6a627842': { name: 'mint(address)', kind: 'mint' },
  '0xa1448194': { name: 'safeMint(address,uint256)', kind: 'mint' },
  '0x40d097c3': { name: 'safeMint(address)', kind: 'mint' },
  '0x1249c58b': { name: 'mint()', kind: 'mint' },
  '0x4e71d92d': { name: 'claim()', kind: 'claim' },
  '0x379607f5': { name: 'claim(uint256)', kind: 'claim' },
};

const SIGNATURES = Object.fromEntries(
  Object.entries(SELECTORS).map(([sel, v]) => [v.name, sel]),
);

module.exports = { SELECTORS, SIGNATURES };
