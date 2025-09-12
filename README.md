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
