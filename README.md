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
