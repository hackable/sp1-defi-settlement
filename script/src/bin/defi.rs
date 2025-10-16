//! Host CLI to execute/prove DeFi settlement verification in SP1.

use alloy_sol_types::SolType;
use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use defi_lib::defi::{SettlementInput, Side};
use defi_lib::SettlementPublicValues;
// no direct signing or hashing in this binary now
use serde::Serialize;
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use std::{fs, path::PathBuf};

pub const DEFI_ELF: &[u8] = include_elf!("program");

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    /// Use a built-in sample scenario.
    #[arg(long)]
    sample: bool,

    /// Number of orders to include in the sample (default: 4, must be even)
    #[arg(long, default_value_t = 4)]
    num_orders: usize,

    /// Export the SettlementInput JSON to the given path (works with --sample)
    #[arg(long)]
    export: Option<String>,

    /// Only export JSON and exit (no execute/prove)
    #[arg(long, default_value_t = false)]
    export_only: bool,

    /// Proof mode to use when generating a proof (core|compressed|plonk|groth16).
    #[arg(long, value_enum, default_value_t = ProofMode::Core)]
    proof_mode: ProofMode,

    /// Write the proof + public values bundle (JSON) to this path.
    #[arg(long)]
    proof_out: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ProofMode {
    Core,
    Compressed,
    Plonk,
    Groth16,
}

impl ProofMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Compressed => "compressed",
            Self::Plonk => "plonk",
            Self::Groth16 => "groth16",
        }
    }
}

#[derive(Serialize)]
struct ProofBundleExport {
    proof_mode: String,
    proof: Option<String>,
    public_values: String,
    balances_root: String,
    prev_filled_root: String,
    filled_root: String,
    prev_cancellations_root: String,
    cancellations_root: String,
    domain_separator: String,
    match_count: u32,
}

fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    let args = Args::parse();
    if args.execute == args.prove {
        anyhow::bail!("You must specify either --execute or --prove");
    }

    let client = ProverClient::from_env();

    // Build input with specified number of orders
    let input = if args.sample {
        build_sample_with_orders(args.num_orders).context("building sample with orders")?
    } else {
        build_sample_input().context("building input")?
    };

    println!(
        "Processing settlement with {} orders ({} matches)...",
        input.orders.len(),
        input.matches.len()
    );

    // Export JSON only if explicitly requested via --export. No default export.
    if let Some(path) = &args.export {
        match export_sample_json(&input, path) {
            Ok(_) => println!("Wrote sample to {}", path),
            Err(e) => eprintln!("Warning: failed to write {}: {}", path, e),
        }
    }

    if args.export_only {
        if args.export.is_none() {
            eprintln!("Nothing exported: provide --export <path>.");
        }
        return Ok(());
    }

    // Prepare stdin and write the input
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    if args.execute {
        let (output, _report) = client
            .execute(DEFI_ELF, &stdin)
            .run()
            .context("execute run failed")?;
        let pv = SettlementPublicValues::abi_decode(output.as_slice())
            .expect("output should decode to SettlementPublicValues");
        println!("\nExecution Results:");
        println!("  Orders: {}", input.orders.len());
        println!("  Matches: {}", pv.matchCount);
        println!("  balancesRoot: 0x{}", hex::encode(pv.balancesRoot));
        println!("  prevFilledRoot: 0x{}", hex::encode(pv.prevFilledRoot));
        println!("  filledRoot: 0x{}", hex::encode(pv.filledRoot));
        println!(
            "  prevCancellationsRoot: 0x{}",
            hex::encode(pv.prevCancellationsRoot)
        );
        println!(
            "  cancellationsRoot: 0x{}",
            hex::encode(pv.cancellationsRoot)
        );
        println!("  domainSeparator: 0x{}", hex::encode(pv.domainSeparator));
        println!("  publicValues ABI: 0x{}", hex::encode(output.as_slice()));
    } else {
        let (pk, vk) = client.setup(DEFI_ELF);
        let proof_mode = args.proof_mode;
        let proof = match proof_mode {
            ProofMode::Core => client
                .prove(&pk, &stdin)
                .core()
                .run()
                .context("failed to generate core proof")?,
            ProofMode::Compressed => client
                .prove(&pk, &stdin)
                .compressed()
                .run()
                .context("failed to generate compressed proof")?,
            ProofMode::Plonk => client
                .prove(&pk, &stdin)
                .plonk()
                .run()
                .context("failed to generate plonk proof")?,
            ProofMode::Groth16 => client
                .prove(&pk, &stdin)
                .groth16()
                .run()
                .context("failed to generate groth16 proof")?,
        };
        println!("Successfully generated {} proof!", proof_mode.as_str());
        client
            .verify(&proof, &vk)
            .context("failed to verify proof")?;
        println!("Successfully verified proof!");
        let pv = SettlementPublicValues::abi_decode(proof.public_values.as_slice())
            .expect("proof public values should decode to SettlementPublicValues");
        let public_values_hex = hex::encode(proof.public_values.as_slice());
        println!("\nProof Results:");
        println!("  Orders: {}", input.orders.len());
        println!("  Matches: {}", pv.matchCount);
        println!("  balancesRoot: 0x{}", hex::encode(pv.balancesRoot));
        println!("  prevFilledRoot: 0x{}", hex::encode(pv.prevFilledRoot));
        println!("  filledRoot: 0x{}", hex::encode(pv.filledRoot));
        println!(
            "  prevCancellationsRoot: 0x{}",
            hex::encode(pv.prevCancellationsRoot)
        );
        println!(
            "  cancellationsRoot: 0x{}",
            hex::encode(pv.cancellationsRoot)
        );
        println!("  domainSeparator: 0x{}", hex::encode(pv.domainSeparator));
        println!("  publicValues ABI: 0x{}", public_values_hex);

        let proof_bytes = match proof_mode {
            ProofMode::Plonk | ProofMode::Groth16 => {
                let bytes = proof.bytes();
                println!(
                    "  Proof bytes ({}): 0x{}",
                    proof_mode.as_str(),
                    hex::encode(&bytes)
                );
                Some(bytes)
            }
            _ => {
                println!(
                    "  Proof bytes: n/a (re-run with --proof-mode=plonk or --proof-mode=groth16 for on-chain verification)"
                );
                None
            }
        };

        if let Some(path) = &args.proof_out {
            let export = ProofBundleExport {
                proof_mode: proof_mode.as_str().to_string(),
                proof: proof_bytes
                    .as_ref()
                    .map(|bytes| format!("0x{}", hex::encode(bytes))),
                public_values: format!("0x{}", public_values_hex),
                balances_root: format!("0x{}", hex::encode(pv.balancesRoot)),
                prev_filled_root: format!("0x{}", hex::encode(pv.prevFilledRoot)),
                filled_root: format!("0x{}", hex::encode(pv.filledRoot)),
                prev_cancellations_root: format!("0x{}", hex::encode(pv.prevCancellationsRoot)),
                cancellations_root: format!("0x{}", hex::encode(pv.cancellationsRoot)),
                domain_separator: format!("0x{}", hex::encode(pv.domainSeparator)),
                match_count: pv.matchCount,
            };
            let json = serde_json::to_string_pretty(&export).context("serialize proof bundle")?;
            fs::write(path, json)
                .with_context(|| format!("write proof bundle to {}", path.display()))?;
            println!("Wrote proof bundle to {}", path.display());
        }
    }
    Ok(())
}

fn build_sample_input() -> Result<SettlementInput> {
    Ok(defi_lib::samples::build_sample_input().map_err(|e| anyhow::anyhow!(e))?)
}

fn build_sample_with_orders(num_orders: usize) -> Result<SettlementInput> {
    Ok(
        defi_lib::samples::build_sample_input_with_orders(num_orders)
            .map_err(|e| anyhow::anyhow!(e))?,
    )
}

// filled_root_from_orders and orders_root_from_list provided by defi_lib::defi

// ----------------- Export sample input as documented JSON -----------------

fn export_sample_json(input: &SettlementInput, filename: &str) -> Result<(), String> {
    use defi_lib::io::json::{
        BalanceJson as JsonBalance, DeltaJson as JsonDelta, DomainJson as JsonDomain,
        InputJson as JsonInput, MatchJson as JsonMatch, OrderJson as JsonOrder,
    };

    fn side_str(s: &Side) -> &'static str {
        match s {
            Side::Buy => "Buy",
            Side::Sell => "Sell",
        }
    }
    fn hex20(b: &[u8; 20]) -> String {
        format!("0x{}", hex::encode(b))
    }
    fn hex32(b: &[u8; 32]) -> String {
        format!("0x{}", hex::encode(b))
    }

    let domain = JsonDomain {
        chain_id: input.domain.chain_id.to_string(),
        exchange: hex20(&input.domain.exchange),
    };
    let orders = input
        .orders
        .iter()
        .map(|o| JsonOrder {
            maker: hex20(&o.maker),
            base: hex32(&o.base),
            quote: hex32(&o.quote),
            side: side_str(&o.side).to_string(),
            price_n: o.price_n.to_string(),
            price_d: o.price_d.to_string(),
            amount: o.amount.to_string(),
            nonce: o.nonce.to_string(),
            expiry: o.expiry.to_string(),
            v: o.v,
            r: hex32(&o.r),
            s: hex32(&o.s),
        })
        .collect();
    let matches = input
        .matches
        .iter()
        .map(|m| JsonMatch {
            buy_idx: m.buy_idx,
            sell_idx: m.sell_idx,
            base_filled: m.base_filled.to_string(),
            quote_paid: m.quote_paid.to_string(),
        })
        .collect();
    let initial_balances = input
        .initial_balances
        .iter()
        .map(|b| JsonBalance {
            owner: hex20(&b.owner),
            asset: hex32(&b.asset),
            amount: b.amount.to_string(),
        })
        .collect();
    let proposed_deltas = input
        .proposed_deltas
        .iter()
        .map(|d| JsonDelta {
            owner: hex20(&d.owner),
            asset: hex32(&d.asset),
            delta: d.delta.to_string(),
        })
        .collect();
    let json = JsonInput {
        domain,
        orders,
        matches,
        initial_balances,
        proposed_deltas,
        timestamp: input.timestamp.to_string(),
        cancellations_updates: None,
        orders_touched: None,
    };

    let out = serde_json::to_string_pretty(&json).map_err(|e| e.to_string())?;
    let path = PathBuf::from(filename);
    std::fs::write(&path, out).map_err(|e| e.to_string())
}

// pubkey_x/pubkey_y no longer needed with signature recovery in the guest
