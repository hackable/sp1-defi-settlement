# Changelog

All notable changes to this repository will be documented in this file.


## 0.2.0
### Added
- DeFi zkVM program (program/) that verifies EIP-712 signed orders, matching constraints,
  recomputed deltas, non-negative balances, and commits public values for on-chain use.
- New library crate name: `defi-lib` (renamed from `fibonacci-lib`).
- Public values ABI (SettlementPublicValues) with:
  - `balancesRoot` (cumulative_owed per (owner, asset))
  - `prevFilledRoot` (binds to prior cumulative filled state)
  - `filledRoot` (new cumulative filled per orderId after this batch)
  - `matchCount`
- Cross-batch overfill prevention in-guest: remaining capacity initialized as
  `amount - prev_filled` (rejects if `prev_filled > amount`).
- Binding to prior state: guest recomputes `prevFilledRoot` from `orders + prev_filled` and fails on
  mismatch.
- Host CLIs (script/):
  - `defi`: sample runner to execute/prove and print `balancesRoot`, `prevFilledRoot`, `filledRoot`.
    - Flags: `--execute|--prove`, `--sample`, `--export <path>`, `--export-only`.
  - `leaves`: compute balances leaves + root from a SettlementInput JSON or built-in sample.
  - `proof`: generate a Merkle proof for (owner, asset) from a leaves JSON.
- Solidity example (contracts/Ledger.sol):
  - Stores `balancesRoot` and `filledRoot`.
  - `updateRoot` verifies SP1 proof, requires `prevFilledRoot == filledRoot`, then atomically updates
    both roots.
  - `withdraw` enforces cumulative_owed − spent via a Merkle proof.
- Documentation:
  - `docs/defi.md`: JSON schema, hashing rules, on-chain integration, CLIs, end-to-end flow.
  - `docs/workflow.md`: step-by-step workflow from proving to withdrawals.
  - `docs/zk-clob.md`: architecture, flow diagrams, and path to a canonical matching (zk CLOB).
- Tests (lib/tests/defi_tests.rs):
  - Successful settlement: asserts `balancesRoot` and `filledRoot`.
  - Invalid signature, price violation, overfill (within-batch), delta mismatch, negative balance.
  - Cross-batch overfill rejected (using `prev_filled`).

### Changed
- Removed Fibonacci demo program and ABI from the library; DeFi-only ABI remains.
- Program now commits `{balancesRoot, prevFilledRoot, filledRoot, matchCount}`.
- Public values expanded to include `{prevCancellationsRoot, cancellationsRoot, domainSeparator}`;
  on-chain contract now updates cancellations root atomically with proof verification.
- `script` runner prints `prevFilledRoot` and `filledRoot` in addition to `balancesRoot`.
- README updated to reference new docs and binaries; trimmed legacy sections.
- Mermaid diagrams sanitized for compatibility in docs.
- Minor performance improvement: avoid redundant sorting when building balancesRoot by leveraging
  BTreeMap’s inherent order.

### Deprecated
- None.

### Removed
- Legacy Fibonacci CLI/program and the `PublicValuesStruct` from the lib’s ABI.
- Old `defi-script`/`defi-program` crates (consolidated into `script` and `program`).

### Fixed
- N/A (functional changes mostly additive or refactors).

### Security
- Cross-batch replay/overfill hardening via `prev_filled_root` binding and remaining-capacity
  logic. Suggested on-chain pattern requires verifying `prevFilledRoot` equals contract’s stored
  `filledRoot` before state advancement.

## 0.1.0
### Added
- Initial SP1 template with a Fibonacci demo and a basic DeFi prototype (pre-cumulative_owed).

### Notes
- This release contained early scaffolding and did not include `filledRoot` nor the
  `prevFilledRoot` binding described above.
