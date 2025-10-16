//! Build a cancellations Merkle root over orderIds where value=1 means canceled, 0 otherwise.

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::Deserialize;

#[derive(Parser, Debug)]
#[command(author, version, about = "Compute cancellationsRoot from orderIds + canceled flags", long_about = None)]
struct Args {
    /// Input JSON file with array of { orderId: 0x..., canceled: true/false }
    #[arg(long, short = 'f')]
    file: Option<String>,

    /// Pretty-print JSON output
    #[arg(long, default_value_t = false)]
    pretty: bool,

    /// Output JSON file path (if omitted, print to stdout)
    #[arg(long)]
    out: Option<String>,

    /// Use built-in sample orderIds (same as sample in other CLIs)
    #[arg(long, default_value_t = false)]
    sample: bool,

    /// For --sample, indices to mark canceled (can be repeated)
    #[arg(long, num_args = 0..)]
    cancel_index: Vec<u32>,
}

#[derive(Deserialize)]
struct JsonCancelItem {
    #[serde(rename = "orderId")]
    order_id: String,
    canceled: bool,
}

fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    defi_lib::parse_hex(s).map_err(|e| anyhow::anyhow!(e))
}

fn main() -> Result<()> {
    let args = Args::parse();
    if !args.sample && args.file.is_none() {
        bail!("provide either --sample or --file <path>");
    }

    let (order_ids, canceled_flags): (Vec<[u8; 32]>, Vec<bool>) = if args.sample {
        // Use the same two orders as the sample in other CLIs to derive orderIds.
        use defi_lib::defi::{addr_from_signer, order_struct_hash, Domain, Order, Side};
        use k256::ecdsa::SigningKey;

        let _domain = Domain {
            chain_id: 1,
            exchange: [0x11; 20],
        };
        let buy_sk = SigningKey::from_bytes((&[1u8; 32]).into())
            .expect("hardcoded key bytes should be valid");
        let sell_sk = SigningKey::from_bytes((&[2u8; 32]).into())
            .expect("hardcoded key bytes should be valid");
        let buyer = addr_from_signer(&buy_sk);
        let seller = addr_from_signer(&sell_sk);
        let base = [0xAA; 32];
        let quote = [0xBB; 32];
        let buy = Order {
            maker: buyer,
            base,
            quote,
            side: Side::Buy,
            price_n: 3,
            price_d: 1,
            amount: 10,
            nonce: 100,
            expiry: u64::MAX,
            v: 27,
            r: [0u8; 32],
            s: [0u8; 32],
        };
        let sell = Order {
            maker: seller,
            base,
            quote,
            side: Side::Sell,
            price_n: 2,
            price_d: 1,
            amount: 10,
            nonce: 200,
            expiry: u64::MAX,
            v: 27,
            r: [0u8; 32],
            s: [0u8; 32],
        };
        let order_ids = vec![order_struct_hash(&buy), order_struct_hash(&sell)];
        let mut canceled_flags = vec![false, false];
        for idx in args.cancel_index {
            if let Some(slot) = canceled_flags.get_mut(idx as usize) {
                *slot = true;
            }
        }
        (order_ids, canceled_flags)
    } else {
        let file = args
            .file
            .as_ref()
            .expect("file argument should be provided when not using sample");
        let data = std::fs::read_to_string(file).with_context(|| format!("reading {}", file))?;
        let items: Vec<JsonCancelItem> =
            serde_json::from_str(&data).context("parsing JSON input")?;
        let mut order_ids = Vec::with_capacity(items.len());
        let mut canceled_flags = Vec::with_capacity(items.len());
        for it in items {
            order_ids.push(parse_hex32(&it.order_id)?);
            canceled_flags.push(it.canceled);
        }
        (order_ids, canceled_flags)
    };

    // Build cancellations_root = merkle_root over leaves H(orderId || value), where value = 1 if canceled else 0
    let entries: Vec<([u8; 32], [u8; 32])> = order_ids
        .iter()
        .enumerate()
        .map(|(i, oid)| {
            let v = if canceled_flags[i] { 1u128 } else { 0u128 };
            (*oid, defi_lib::merkle::hash_filled_leaf(*oid, v))
        })
        .collect();
    let root = defi_lib::merkle::merkle_root_from_unordered_kv(entries);

    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct JsonOutLeaf {
        order_id: String,
        canceled: bool,
    }
    #[derive(serde::Serialize)]
    struct Output {
        root: String,
        leaves: Vec<JsonOutLeaf>,
    }
    let leaves: Vec<JsonOutLeaf> = order_ids
        .iter()
        .enumerate()
        .map(|(i, oid)| JsonOutLeaf {
            order_id: format!("0x{}", hex::encode(oid)),
            canceled: canceled_flags[i],
        })
        .collect();
    let out = Output {
        root: format!("0x{}", hex::encode(root)),
        leaves,
    };
    let s = if args.pretty {
        serde_json::to_string_pretty(&out)?
    } else {
        serde_json::to_string(&out)?
    };
    if let Some(path) = args.out {
        std::fs::write(&path, s).with_context(|| format!("writing {}", path))?;
    } else {
        println!("{}", s);
    }
    Ok(())
}
