# SP1 DeFi Settlement Template

This repository demonstrates an end-to-end [SP1](https://github.com/succinctlabs/sp1) project that
generates zero-knowledge proofs for off-chain order matching with **sparse Merkle tree updates**,
enabling billion-order scale settlement with O(T log N) complexity where T is touched orders.


## Key Features

- **Sparse Merkle Updates**: Only updates touched orders (O(T log N) vs O(N))
- **Signature Recovery**: Eliminates pubkey storage using EIP-712 + recovery
- **Cancellation Support**: Monotonic cancellation tree with sparse updates
- **Cumulative Owed Model**: Withdraw-friendly balance tracking
- **SP1 Precompiles**: Hardware-accelerated Keccak and ECDSA verification
- **Production Ready**: Overflow protection, deterministic processing, attack mitigations

## Requirements

- [Rust](https://rustup.rs/)
- [SP1](https://docs.succinct.xyz/docs/sp1/getting-started/install)

## Running the Project

The program is automatically built through `script/build.rs` when the script is built.

### DeFi Settlement (Sample)

- Execute without generating a proof (debugging):
  ```sh
  cd script
  cargo run --release -- --execute --sample --num-orders 6
  ```
  The `--num-orders` flag is optional (defaults to 4 orders and must remain even).

- Generate an SP1 core proof (local verify):
  ```sh
  cd script
  SP1_PROVER=cpu cargo run --release -- --prove --sample --num-orders 6
  ```
  Drop `--num-orders` to use the default sample size, or choose any even count to scale the demo batch.

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

### Input JSON Format

The settlement input JSON supports both simple batches and optimized sparse updates:

**Order fields** (camelCase):
- `maker` (0x20-bytes), `base` (0x32-bytes), `quote` (0x32-bytes)
- `side` ("Buy" | "Sell"), `price_n`, `price_d`, `amount` (decimal strings)
- `nonce`, `expiry` (decimal strings)
- `v` (27/28), `r` (0x32-bytes), `s` (0x32-bytes) - signature components

**Optional fields** for sparse updates:
- `cancellationsUpdates`: Array of cancellation state changes
- `ordersTouched`: Pre-computed proofs for touched orders (advanced)

**Signature requirements**:
- `v` must be 27 or 28
- `s` must be canonical (low‑s): `s <= secp256k1_n/2`
- `r` and `s` must be non‑zero
- Signatures use EIP-712 with recovery (no pubkey storage needed)

# End-to-End Workflow (Simple Guide)

## Concepts
- **Batch proof (SP1 proof)**: Proves the entire settlement and advances state roots.
  - Public values: `balancesRoot`, `prevFilledRoot`, `filledRoot`, `cancellationsRoot`, `domainSeparator`, `matchCount`.
  - On‑chain updates all roots atomically, binding to domain (chainId, exchange).
- **Sparse Updates**: Only touches matched orders, enabling billion-order scale.
- **Membership proof (Merkle proof)**: Per user; proves their cumulative_owed under the current `balancesRoot` to withdraw.

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
- **SP1 proof** = for the batch (updates all state roots atomically on-chain).
- **Merkle proof** = per user (withdraws against the current `balancesRoot`).
- **Cumulative owed model**: Contract tracks `spent[owner][asset]`; withdraw allowed iff `spent + amountToWithdraw <= cumulativeOwed`.
- **Sparse updates**: Only touched orders need proofs, enabling massive scale.
- **Cancellations**: Monotonic tree (can cancel but not un-cancel), verified via sparse proofs.
- **Security**: Canonical signatures, overflow protection, deterministic processing, ghost order prevention.


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

## Architecture & Performance

### Codebase Structure
- **`lib/`**: Core settlement logic with modular organization
  - `defi`: Settlement verification, EIP-712, signature recovery
  - `merkle`: Sparse Merkle tree operations
  - `util`: Parsing utilities
  - `io`: JSON type definitions
  - `samples`: Sample data builders
- **`program/`**: SP1 guest program (zkVM)
- **`script/`**: CLI tools (defi, leaves, proof, cancellations, orderids)

### Performance Optimizations

**Sparse Updates**
- The guest updates `filledRoot` using sparse leaf updates (O(T log N)) over only the touched orders.
- Supports billion-order books with only ~1000 touched orders per batch.
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

## Technical Details

### Crypto Consistency

- **Unified library**: Both host (scripts/tests) and guest (program) use `k256` for ECDSA and `sha3` for Keccak.
- **Signature recovery**: Orders carry `(v, r, s)` only. The guest recovers the public key from the EIP‑712 digest and derives the `maker` address.
- **Computing `v`**: The host determines `v` by attempting recovery with `RecoveryId` 0 and 1; whichever matches maps to `v = 27` or `28`.
- **Precompiles**: SP1-patched crates route Keccak and ECDSA to hardware-accelerated precompiles (~100-500 constraints vs 10,000+).

### Security Features

- **Canonical signatures**: Enforces low-s to prevent malleability
- **Overflow protection**: All arithmetic uses checked operations
- **Deterministic processing**: Sorted order processing prevents non-determinism
- **Ghost order prevention**: Touched orders must be matched in batch
- **Attack mitigations**: DoS limits (1000 touched orders), tree depth limits (50 levels)
- **Monotonic cancellations**: Orders can be canceled but never un-canceled
