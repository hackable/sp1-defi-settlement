//! Host CLI to execute/prove DeFi settlement verification in SP1.

use alloy_sol_types::SolType;
use anyhow::{Context, Result};
use clap::Parser;
use defi_lib::defi::{SettlementInput, Side};
use defi_lib::SettlementPublicValues;
// no direct signing or hashing in this binary now
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use std::path::PathBuf;

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

    /// Export the SettlementInput JSON to the given path (works with --sample)
    #[arg(long)]
    export: Option<String>,

    /// Only export JSON and exit (no execute/prove)
    #[arg(long, default_value_t = false)]
    export_only: bool,
}

fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    let args = Args::parse();
    if args.execute == args.prove {
        anyhow::bail!("You must specify either --execute or --prove");
    }

    let client = ProverClient::from_env();

    // Build input (sample for now)
    let input = if args.sample {
        build_sample_input().context("building sample input")?
    } else {
        build_sample_input().context("building input")?
    };

    // Export JSON only if explicitly requested via --export. No default export.
    let mut exported = false;
    if let Some(path) = &args.export {
        match export_sample_json(&input, path) {
            Ok(_) => { println!("Wrote {}", path); exported = true; },
            Err(e) => eprintln!("Warning: failed to write {}: {}", path, e),
        }
    }

    if args.export_only {
        if !exported {
            eprintln!("Nothing exported: provide --export <path>.");
        }
        return Ok(());
    }

    // Prepare stdin and write the input
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    if args.execute {
        let (output, _report) = client.execute(DEFI_ELF, &stdin).run().context("execute run failed")?;
        let pv = SettlementPublicValues::abi_decode(output.as_slice()).unwrap();
        println!("matchCount: {}", pv.matchCount);
        println!("balancesRoot: 0x{}", hex::encode(pv.balancesRoot));
        println!("prevFilledRoot: 0x{}", hex::encode(pv.prevFilledRoot));
        println!("filledRoot: 0x{}", hex::encode(pv.filledRoot));
        println!("cancellationsRoot: 0x{}", hex::encode(pv.cancellationsRoot));
    } else {
        let (pk, vk) = client.setup(DEFI_ELF);
        let proof = client.prove(&pk, &stdin).run().context("failed to generate proof")?;
        println!("Successfully generated proof!");
        client.verify(&proof, &vk).context("failed to verify proof")?;
        println!("Successfully verified proof!");
        let pv = SettlementPublicValues::abi_decode(proof.public_values.as_slice()).unwrap();
        println!("matchCount: {}", pv.matchCount);
        println!("balancesRoot: 0x{}", hex::encode(pv.balancesRoot));
        println!("prevFilledRoot: 0x{}", hex::encode(pv.prevFilledRoot));
        println!("filledRoot: 0x{}", hex::encode(pv.filledRoot));
        println!("cancellationsRoot: 0x{}", hex::encode(pv.cancellationsRoot));
    }
    Ok(())
}

fn build_sample_input() -> Result<SettlementInput> {
    Ok(defi_lib::samples::build_sample_input().map_err(|e| anyhow::anyhow!(e))?)
}

// filled_root_from_orders and orders_root_from_list provided by defi_lib::defi

// ----------------- Export sample input as documented JSON -----------------

fn export_sample_json(input: &SettlementInput, filename: &str) -> Result<(), String> {
    use defi_lib::io::json::{DomainJson as JsonDomain, OrderJson as JsonOrder, MatchJson as JsonMatch, BalanceJson as JsonBalance, DeltaJson as JsonDelta, InputJson as JsonInput};

    fn side_str(s: &Side) -> &'static str { match s { Side::Buy => "Buy", Side::Sell => "Sell" } }
    fn hex20(b: &[u8; 20]) -> String { format!("0x{}", hex::encode(b)) }
    fn hex32(b: &[u8; 32]) -> String { format!("0x{}", hex::encode(b)) }

    let domain = JsonDomain { chain_id: input.domain.chain_id.to_string(), exchange: hex20(&input.domain.exchange) };
    let orders = input.orders.iter().map(|o| JsonOrder {
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
    }).collect();
    let matches = input.matches.iter().map(|m| JsonMatch {
        buy_idx: m.buy_idx,
        sell_idx: m.sell_idx,
        base_filled: m.base_filled.to_string(),
        quote_paid: m.quote_paid.to_string(),
    }).collect();
    let initial_balances = input.initial_balances.iter().map(|b| JsonBalance {
        owner: hex20(&b.owner),
        asset: hex32(&b.asset),
        amount: b.amount.to_string(),
    }).collect();
    let proposed_deltas = input.proposed_deltas.iter().map(|d| JsonDelta {
        owner: hex20(&d.owner),
        asset: hex32(&d.asset),
        delta: d.delta.to_string(),
    }).collect();
    let json = JsonInput { domain, orders, matches, initial_balances, proposed_deltas, timestamp: input.timestamp.to_string() };

    let out = serde_json::to_string_pretty(&json).map_err(|e| e.to_string())?;
    let path = PathBuf::from(filename);
    std::fs::write(&path, out).map_err(|e| e.to_string())
}

// pubkey_x/pubkey_y no longer needed with signature recovery in the guest
