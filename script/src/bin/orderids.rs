//! Extract orderIds from a SettlementInput JSON (or built-in sample) and emit
//! a cancellations template array: [{ orderId, canceled: false }, ...].

use anyhow::{bail, Context, Result};
use clap::Parser;
// no local JSON types needed here
use defi_lib::io::json as iojson;
use defi_lib::defi::{Order as LibOrder, order_struct_hash};

#[derive(Parser, Debug)]
#[command(author, version, about = "Dump orderIds and a cancellations template", long_about = None)]
struct Args {
    /// Input SettlementInput JSON path (as documented for leaves CLI)
    #[arg(long, short = 'f')]
    file: Option<String>,

    /// Pretty-print JSON output
    #[arg(long, default_value_t = false)]
    pretty: bool,

    /// Output JSON file path (if omitted, print to stdout)
    #[arg(long)]
    out: Option<String>,

    /// Use built-in sample orders instead of a file
    #[arg(long, default_value_t = false)]
    sample: bool,
}

// Minimal subset: reuse shared types
type JsonOrder = iojson::OrderJson;
type JsonInput = iojson::InputJson;

fn order_id_from_json(o: &JsonOrder) -> Result<[u8; 32]> {
    let maker = defi_lib::parse_hex::<20>(&o.maker).map_err(|e| anyhow::anyhow!(e))?;
    let base = defi_lib::parse_hex::<32>(&o.base).map_err(|e| anyhow::anyhow!(e))?;
    let quote = defi_lib::parse_hex::<32>(&o.quote).map_err(|e| anyhow::anyhow!(e))?;
    let side = defi_lib::to_side(&o.side).map_err(|e| anyhow::anyhow!(e))?;
    let price_n = defi_lib::to_u128(&o.price_n).map_err(|e| anyhow::anyhow!(e))?;
    let price_d = defi_lib::to_u128(&o.price_d).map_err(|e| anyhow::anyhow!(e))?;
    let amount = defi_lib::to_u128(&o.amount).map_err(|e| anyhow::anyhow!(e))?;
    let nonce = defi_lib::to_u64(&o.nonce).map_err(|e| anyhow::anyhow!(e))?;
    let expiry = defi_lib::to_u64(&o.expiry).map_err(|e| anyhow::anyhow!(e))?;
    let v = 0u8;
    let r = [0u8; 32];
    let s = [0u8; 32];
    let order = LibOrder { maker, base, quote, side, price_n, price_d, amount, nonce, expiry, v, r, s };
    Ok(order_struct_hash(&order))
}

// Removed local sample builder; use defi_lib::samples instead

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CancelTemplateItem { order_id: String, canceled: bool }

fn main() -> Result<()> {
    let args = Args::parse();
    if !args.sample && args.file.is_none() { bail!("provide either --sample or --file <path>"); }

    let order_ids: Vec<[u8; 32]> = if args.sample {
        // Use shared sample builder and map to order IDs
        let input = defi_lib::samples::build_sample_input().map_err(|e| anyhow::anyhow!(e))?;
        input.orders.iter().map(|o| order_struct_hash(o)).collect()
    } else {
        let file = args.file.as_ref().unwrap();
        let data = std::fs::read_to_string(file).with_context(|| format!("reading {}", file))?;
        let json: JsonInput = serde_json::from_str(&data).context("parsing JSON input")?;
        json.orders.iter().map(|o| order_id_from_json(o)).collect::<Result<Vec<_>>>()?
    };

    let mut items: Vec<CancelTemplateItem> = Vec::with_capacity(order_ids.len());
    for oid in &order_ids {
        items.push(CancelTemplateItem { order_id: format!("0x{}", hex::encode(oid)), canceled: false });
    }
    let s = if args.pretty { serde_json::to_string_pretty(&items)? } else { serde_json::to_string(&items)? };
    if let Some(path) = args.out { std::fs::write(&path, s).with_context(|| format!("writing {}", path))?; } else { println!("{}", s); }
    Ok(())
}
