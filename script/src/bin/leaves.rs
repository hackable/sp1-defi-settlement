//! Build final balances leaves and Merkle root from a SettlementInput JSON, validating via the library.

use anyhow::{bail, Context, Result};
use clap::Parser;
use defi_lib::defi::{
    compute_final_entries, SettlementInput,
    order_struct_hash, orders_root_from_list, filled_root_from_orders,
};
// serde is only used via types imported from the shared io module
use defi_lib::io::json as iojson;
use sha3::{Digest, Keccak256};

#[derive(Parser, Debug)]
#[command(author, version, about = "Compute leaves and Merkle root from a SettlementInput JSON", long_about = None)]
struct Args {
    /// Input JSON file path (hex-string format as documented)
    #[arg(long, short = 'f')]
    file: Option<String>,

    /// Output JSON file path (if omitted, print to stdout)
    #[arg(long)]
    out: Option<String>,

    /// Pretty-print JSON output
    #[arg(long, default_value_t = false)]
    pretty: bool,

    /// Use built-in sample input instead of reading a file
    #[arg(long, default_value_t = false)]
    sample: bool,
}

// Mirror the documented JSON format (hex strings and decimal strings)
type JsonOrder = iojson::OrderJson;
type JsonInput = iojson::InputJson;

// no local Asset alias needed

// Use helpers directly from the library
use defi_lib::{parse_hex, to_u128, to_u64, to_i128, to_side};

fn order_to_native(j: JsonOrder) -> Result<defi_lib::defi::Order> {
    Ok(defi_lib::defi::Order {
        maker: parse_hex(&j.maker).map_err(|e| anyhow::anyhow!(e))?,
        base: parse_hex(&j.base).map_err(|e| anyhow::anyhow!(e))?,
        quote: parse_hex(&j.quote).map_err(|e| anyhow::anyhow!(e))?,
        side: to_side(&j.side).map_err(|e| anyhow::anyhow!(e))?,
        price_n: to_u128(&j.price_n).map_err(|e| anyhow::anyhow!(e))?,
        price_d: to_u128(&j.price_d).map_err(|e| anyhow::anyhow!(e))?,
        amount: to_u128(&j.amount).map_err(|e| anyhow::anyhow!(e))?,
        nonce: to_u64(&j.nonce).map_err(|e| anyhow::anyhow!(e))?,
        expiry: to_u64(&j.expiry).map_err(|e| anyhow::anyhow!(e))?,
        v: j.v,
        r: parse_hex(&j.r).map_err(|e| anyhow::anyhow!(e))?,
        s: parse_hex(&j.s).map_err(|e| anyhow::anyhow!(e))?,
    })
}

fn input_to_native(j: JsonInput) -> Result<SettlementInput> {
    use defi_lib::defi::{Balance, Delta, Domain, MatchFill, SettlementInput};
    let domain = Domain {
        chain_id: to_u64(&j.domain.chain_id).map_err(|e| anyhow::anyhow!(e))?,
        exchange: parse_hex(&j.domain.exchange).map_err(|e| anyhow::anyhow!(e))?,
    };
    let orders = j.orders.into_iter().map(order_to_native).collect::<Result<Vec<_>>>()?;
    let matches = j.matches.into_iter().map(|m| -> Result<MatchFill> {
        Ok(MatchFill {
            buy_idx: m.buy_idx,
            sell_idx: m.sell_idx,
            base_filled: to_u128(&m.base_filled).map_err(|e| anyhow::anyhow!(e))?,
            quote_paid: to_u128(&m.quote_paid).map_err(|e| anyhow::anyhow!(e))?,
        })
    }).collect::<Result<Vec<_>>>()?;
    let initial_balances = j.initial_balances.into_iter().map(|b| -> Result<Balance> {
        Ok(Balance {
            owner: parse_hex(&b.owner).map_err(|e| anyhow::anyhow!(e))?,
            asset: parse_hex(&b.asset).map_err(|e| anyhow::anyhow!(e))?,
            amount: to_u128(&b.amount).map_err(|e| anyhow::anyhow!(e))?,
        })
    }).collect::<Result<Vec<_>>>()?;
    let proposed_deltas = j.proposed_deltas.into_iter().map(|d| -> Result<Delta> {
        Ok(Delta {
            owner: parse_hex(&d.owner).map_err(|e| anyhow::anyhow!(e))?,
            asset: parse_hex(&d.asset).map_err(|e| anyhow::anyhow!(e))?,
            delta: to_i128(&d.delta).map_err(|e| anyhow::anyhow!(e))?,
        })
    }).collect::<Result<Vec<_>>>()?;
    // Default prev_filled_root to empty and prev_filled to zeros; callers can override by providing a richer JSON
    let prev_filled = vec![0u128; orders.len()];
    let mut prev_filled_root = [0u8; 32];
    prev_filled_root.copy_from_slice(&Keccak256::digest([]));
    // For optimized path, compute orders_root and leave orders_touched empty (this CLI focuses on balances).
    let order_ids: Vec<[u8; 32]> = orders.iter().map(|o| order_struct_hash(o)).collect();
    let orders_root = orders_root_from_list(&order_ids);
    // Compute cancellations_root as parallel tree with value=0 for all orders by default.
    let zero_vals: Vec<u128> = vec![0u128; orders.len()];
    let cancellations_root = filled_root_from_orders(&orders.iter().collect::<Vec<_>>(), &zero_vals);
    // Parse cancellations_updates if present
    let cancellations_updates = if let Some(upds) = j.cancellations_updates {
        upds.into_iter().map(|u| -> Result<defi_lib::defi::CancellationUpdate> {
            Ok(defi_lib::defi::CancellationUpdate {
                order_id: parse_hex(&u.order_id).map_err(|e| anyhow::anyhow!(e))?,
                prev_value: to_u128(&u.prev_value).map_err(|e| anyhow::anyhow!(e))?,
                new_value: to_u128(&u.new_value).map_err(|e| anyhow::anyhow!(e))?,
                proof: u.proof.into_iter().map(|h| parse_hex(&h).map_err(|e| anyhow::anyhow!(e))).collect::<Result<Vec<_>>>()?,
            })
        }).collect::<Result<Vec<_>>>()?
    } else { vec![] };
    Ok(SettlementInput {
        domain,
        orders,
        matches,
        initial_balances,
        proposed_deltas,
        timestamp: to_u64(&j.timestamp).map_err(|e| anyhow::anyhow!(e))?,
        prev_filled_root,
        prev_filled,
        cancellations_root,
        cancellations_updates,
        orders_root,
        orders_touched: vec![],
    })
}

use defi_lib::merkle::{hash_balances_leaf as leaf_hash, merkle_root_from_leaves};

// Use library merkle_root_from_leaves instead of ad hoc

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct LeafOut { owner: String, asset: String, amount: String }

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Output { root: String, match_count: u32, leaves: Vec<LeafOut> }

fn main() -> Result<()> {
    let args = Args::parse();
    // Require either --sample or --file
    if !args.sample && args.file.is_none() {
        bail!("provide either --sample or --file <path>");
    }

    let native_in = if args.sample {
        defi_lib::samples::build_sample_input().map_err(|e| anyhow::anyhow!(e))?
    } else {
        let file = args.file.as_ref().expect("file argument should be provided when not using sample");
        let data = std::fs::read_to_string(file).with_context(|| format!("reading {}", file))?;
        let json_in: JsonInput = serde_json::from_str(&data).context("parsing JSON input")?;
        input_to_native(json_in)?
    };

    // Validate and compute final entries via library
    let entries = compute_final_entries(&native_in).map_err(|e| anyhow::anyhow!("settlement verification failed: {}", e))?;
    // Build leaves and root
    let mut leaves_vec = Vec::with_capacity(entries.len());
    let mut hashes = Vec::with_capacity(entries.len());
    for (owner, asset, amount) in entries.iter().copied() {
        leaves_vec.push(LeafOut { owner: format!("0x{}", hex::encode(owner)), asset: format!("0x{}", hex::encode(asset)), amount: amount.to_string() });
        hashes.push(leaf_hash(owner, asset, amount));
    }
    let root = merkle_root_from_leaves(hashes);

    let out = Output { root: format!("0x{}", hex::encode(root)), match_count: native_in.matches.len() as u32, leaves: leaves_vec };
    let s = if args.pretty { serde_json::to_string_pretty(&out) } else { serde_json::to_string(&out) }?;

    if let Some(path) = args.out {
        std::fs::write(&path, s).with_context(|| format!("writing {}", path))?;
    } else {
        println!("{}", s);
    }
    Ok(())
}

// orders_root_from_list & filled_root_from_orders available from defi_lib::defi

// ===== Sample input (same as in docs/tests) =====
// addr_from_signer, eip712_domain_separator, order_struct_hash, sign_order provided by defi_lib::defi

// Sample input builder moved to defi_lib::samples::build_sample_input
