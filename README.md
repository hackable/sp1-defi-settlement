# SP1 DeFi Settlement Template

This repository demonstrates an end-to-end [SP1](https://github.com/succinctlabs/sp1) project that
generates proofs for an off-chain order matching batch and commits a balances root suitable for
on-chain verification and withdrawals.


## Requirements

- [Rust](https://rustup.rs/)
- [SP1](https://docs.succinct.xyz/docs/sp1/getting-started/install)

## Running the Project

The program is automatically built through `script/build.rs` when the script is built.

### DeFi Settlement (Sample)

- Execute without generating a proof (debugging):
  ```sh
  cd script
  cargo run --release -- --execute --sample
  ```

- Generate an SP1 core proof (local verify):
  ```sh
  cd script
  cargo run --release -- --prove --sample
  ```

### Leaves Dataset Builder

Compute the balances leaves and Merkle root from a SettlementInput JSON or the built-in sample:

- From a JSON file:
  ```sh
  cd script
  cargo run --release --bin leaves -- --file path/to/settlement_input.json --out leaves.json --pretty
  ```

- Built-in sample (no file required):
  ```sh
  cd script
  cargo run --release --bin leaves -- --sample --out leaves.json --pretty
  ```

### Merkle Proof Generator

Generate a per-user proof for `(owner, asset)` from a leaves JSON:

```sh
cd script
cargo run --release --bin proof -- \
  --file leaves.json \
  --owner 0xYourAddress20Bytes \
  --asset 0xYourAssetBytes32 \
  --pretty
```

### Cancellations Builder

Build a `cancellationsRoot` over order IDs, where value=1 means canceled and 0 means active. The settlement proof requires a 0‑value proof for each touched order and binds to the `cancellationsRoot` provided on‑chain.

- From a JSON file of `{ orderId, canceled }` entries:
  ```sh
  cd script
  cargo run --release --bin cancellations -- --file cancellations_input.json --pretty --out cancellations.json
  ```

- Built‑in sample (two orders): cancel the first by index:
  ```sh
  cd script
  cargo run --release --bin cancellations -- --sample --cancel-index 0 --pretty
  ```

### Generate Cancellations Template From Settlement Input

Create a `cancellations_input.json` from a SettlementInput JSON by extracting order IDs (defaults all to `canceled: false`). Edit the flags you want to cancel, then build the root with the cancellations builder above.

```sh
cd script
# From your own SettlementInput JSON
cargo run --release --bin orderids -- --file path/to/settlement_input.json --pretty --out cancellations_input.json
# Or from the built-in sample
cargo run --release --bin orderids -- --sample --pretty --out cancellations_input.json
```

### Input JSON Format (Orders)

Orders no longer include pubkey coordinates; signatures are verified via recovery from `(v, r, s)`.

- order fields (camelCase):
  - `maker` (0x20-bytes), `base` (0x32-bytes), `quote` (0x32-bytes)
  - `side` ("Buy" | "Sell"), `price_n`, `price_d`, `amount` (decimal strings)
  - `nonce`, `expiry` (decimal strings)
- `v` (27/28), `r` (0x32-bytes), `s` (0x32-bytes)

Signature requirements:
- `v` must be 27 or 28.
- `s` must be canonical (low‑s): `s <= secp256k1_n/2`.
- `r` and `s` must be non‑zero.

# End-to-End Workflow (Simple Guide)

## Concepts
- Batch proof (SP1 proof): Proves the entire settlement and advances state roots.
  - Public values: `balancesRoot`, `prevFilledRoot`, `filledRoot`, `matchCount`.
  - On‑chain updates both `balancesRoot` and `filledRoot` atomically, requiring `prevFilledRoot == filledRoot`.
- Membership proof (Merkle proof): Per user; proves their cumulative_owed under the current `balancesRoot` to withdraw.

## Binaries You Have
- `script/bin/defi`: runs/proves a sample batch (prints `balancesRoot`, `prevFilledRoot`, `filledRoot`).
- `script/bin/leaves`: builds the leaves dataset and Merkle root from input (either sample or a JSON file).
- `script/bin/proof`: generates a Merkle proof for a specific `(owner, asset)` from a leaves JSON.

## Quick Start (Sample Batch)
1) Generate the SP1 batch proof and get the roots
- `cd script`
- `cargo run --release -- --prove --sample`
- Copy the printed `balancesRoot`, `prevFilledRoot`, `filledRoot` and the raw `publicValues` (for on‑chain update).

2) Build the leaves dataset for the same batch and check the root matches
- `cargo run --release --bin leaves -- --sample --out leaves.json --pretty`
- Open `leaves.json` and confirm `root` equals the `balancesRoot` from step 1.

3) Generate a user’s Merkle proof (to withdraw later)
- Pick an `owner` and `asset` from `leaves.json`.
- `cargo run --release --bin proof -- --file leaves.json --owner 0xOwner20 --asset 0xAsset32 --pretty`
- Output includes: `amount` (this equals cumulative_owed), `root`, and `proof[]` (siblings).

## On-Chain (Sample Batch)
4) Update the on-chain roots (batch proof)
- Call your Solidity `updateRoot(proof, publicValues)` (see `contracts/Ledger.sol`).
- The contract verifies the proof and requires `prevFilledRoot` in `publicValues` to equal the stored `filledRoot`, then updates both `balancesRoot` and `filledRoot` to the new values.
- The SP1 proof also commits `cancellationsRoot` and binds to the on‑chain view; batches cannot ignore newly canceled orders.
- This uses the SP1 proof from step 1, not the Merkle proof.

5) Withdraw (membership proof)
- Call `withdraw(owner, asset, cumulativeOwed, amountToWithdraw, proof[])` using the output from the `proof` CLI (`amount` → `cumulativeOwed`).



## What to Remember
- SP1 proof = for the batch (updates `balancesRoot` and `filledRoot` on-chain; binds to `prevFilledRoot`).
- Merkle proof = per user (withdraws against the current `balancesRoot`).
- cumulative_owed model: contract tracks `spent[owner][asset]`; withdraw allowed iff `spent + amountToWithdraw <= cumulativeOwed`.
- Roots must match: `leaves.json.root` must equal the `balancesRoot` printed by `defi` (or your custom batch prover) for that batch.
- cancellationsRoot: parallel tree over orderIds with 0/1 values; settlement verifies touched orders are not canceled (0) and binds to the on‑chain `cancellationsRoot`.


## Using the Prover Network

We highly recommend using the [Succinct Prover Network](https://docs.succinct.xyz/docs/network/introduction) for any non-trivial programs or benchmarking purposes. For more information, see the [key setup guide](https://docs.succinct.xyz/docs/network/developers/key-setup) to get started.

To get started, copy the example environment file:

```sh
cp .env.example .env
```

Then, set the `SP1_PROVER` environment variable to `network` and set the `NETWORK_PRIVATE_KEY`
environment variable to your whitelisted private key.

For example, to generate a core proof using the prover network for the sample batch:

```sh
cd script
SP1_PROVER=network NETWORK_PRIVATE_KEY=... cargo run --release -- --prove --sample
```

## Performance Notes

**Sparse Updates**
- The guest updates `filledRoot` using sparse leaf updates (O(T log N)) over only the touched orders.
- This avoids recomputing over the full order set and scales to very large books.

**Precompiles (Patched Crates)**
- The workspace patches `k256` and `sha3` to SP1‑patched crates so guest builds use SP1 precompiles:
  - secp256k1 ECDSA verify (via `k256`) for order signature checks.
  - Keccak hashing (via `sha3`) for Merkle parents/leaves and EIP‑712 hashes.
- Host/tests keep standard Rust crypto; no code changes required.

**Prover Selection**
- Choose the prover backend with `SP1_PROVER`:
  - `cpu` for local proving on CPU.
  - `cuda` for local proving with GPU acceleration (if available).
  - `network` to use the Succinct Prover Network (requires `NETWORK_PRIVATE_KEY`).
  - `mock` for fastest development-only runs (non-cryptographic).

Examples:
```sh
# Local CPU
cd script && SP1_PROVER=cpu cargo run --release -- --prove --sample

# Local GPU
cd script && SP1_PROVER=cuda cargo run --release -- --prove --sample

# Network (requires setup)
cd script && SP1_PROVER=network NETWORK_PRIVATE_KEY=... cargo run --release -- --prove --sample
```

**Troubleshooting**
- If you see a message about patch sections being ignored, ensure the patches live in the workspace root `Cargo.toml` (already configured in this repo).
- If SP1 assets fail to download during build, verify network access and retry the `cargo build` for `script`.

## Crypto Consistency

- Unified library: both the host (scripts/tests) and the guest (program) use `k256` for ECDSA and `sha3` for Keccak.
- Signature scheme: orders carry `(v, r, s)` only. The guest recovers the public key from the EIP‑712 digest and `(v, r, s)`, then derives the `maker` address from the recovered pubkey.
- Computing `v`: the host computes `r, s` using `k256::ecdsa::SigningKey::sign_digest`, then determines `v` by attempting recovery with `RecoveryId` 0 and 1; whichever matches the signer’s verifying key maps to `v = 27` or `28`.
- Precompiles: when compiled for the guest, patched crates route Keccak and ECDSA verify to SP1 precompiles for performance; host/tests use the standard Rust implementations.
