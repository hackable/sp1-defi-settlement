//! Extract orderIds from a SettlementInput JSON (or built-in sample) and emit
//! a cancellations template array: [{ orderId, canceled: false }, ...].

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::Deserialize;
use sha3::{Digest, Keccak256};

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

// Minimal subset of the SettlementInput JSON we need (orders only, same field names)
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonOrder {
    maker: String,
    base: String,
    quote: String,
    side: String,
    price_n: String,
    price_d: String,
    amount: String,
    nonce: String,
    expiry: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonInput { orders: Vec<JsonOrder> }

type Address = [u8; 20];
type Asset = [u8; 32];

fn parse_hex<const N: usize>(s: &str) -> Result<[u8; N]> {
    let ss = s.strip_prefix("0x").context("missing 0x prefix")?;
    if ss.len() != N * 2 { bail!("expected {} hex chars, got {}", N * 2, ss.len()); }
    let mut out = [0u8; N];
    hex::decode_to_slice(ss, &mut out).context("invalid hex")?;
    Ok(out)
}

fn to_u128(s: &str) -> Result<u128> { s.parse().context("invalid u128") }
fn to_u64(s: &str) -> Result<u64> { s.parse().context("invalid u64") }

#[derive(Clone, Copy)]
enum Side { Buy, Sell }

fn to_side(s: &str) -> Result<Side> {
    match s { "Buy" | "buy" => Ok(Side::Buy), "Sell" | "sell" => Ok(Side::Sell), _ => bail!("invalid side") }
}

struct OrderNative {
    maker: Address,
    base: Asset,
    quote: Asset,
    side: Side,
    price_n: u128,
    price_d: u128,
    amount: u128,
    nonce: u64,
    expiry: u64,
}

fn order_struct_hash(o: &OrderNative) -> [u8; 32] {
    // keccak256(abi.encode(
    //   keccak256("Order(address maker,bytes32 base,bytes32 quote,uint8 side,uint128 price_n,uint128 price_d,uint128 amount,uint64 nonce,uint64 expiry)"), ...))
    let mut keccak = Keccak256::new();
    keccak.update(b"Order(address maker,bytes32 base,bytes32 quote,uint8 side,uint128 price_n,uint128 price_d,uint128 amount,uint64 nonce,uint64 expiry)");
    let typehash = keccak.finalize();

    let mut e = Keccak256::new();
    e.update(&typehash);
    let mut maker_buf = [0u8; 32];
    maker_buf[12..].copy_from_slice(&o.maker);
    e.update(&maker_buf);
    e.update(&o.base);
    e.update(&o.quote);
    let mut side_buf = [0u8; 32];
    side_buf[31] = match o.side { Side::Buy => 0, Side::Sell => 1 };
    e.update(&side_buf);
    let mut u128buf = [0u8; 32];
    u128buf[16..].copy_from_slice(&o.price_n.to_be_bytes());
    e.update(&u128buf);
    u128buf[16..].copy_from_slice(&o.price_d.to_be_bytes());
    e.update(&u128buf);
    u128buf[16..].copy_from_slice(&o.amount.to_be_bytes());
    e.update(&u128buf);
    let mut u64buf = [0u8; 32];
    u64buf[24..].copy_from_slice(&o.nonce.to_be_bytes());
    e.update(&u64buf);
    u64buf[24..].copy_from_slice(&o.expiry.to_be_bytes());
    e.update(&u64buf);
    let out = e.finalize();
    let mut sh = [0u8; 32];
    sh.copy_from_slice(&out);
    sh
}

fn json_to_orders(j: JsonInput) -> Result<Vec<OrderNative>> {
    j.orders
        .into_iter()
        .map(|o| -> Result<OrderNative> {
            Ok(OrderNative {
                maker: parse_hex(&o.maker)?,
                base: parse_hex(&o.base)?,
                quote: parse_hex(&o.quote)?,
                side: to_side(&o.side)?,
                price_n: to_u128(&o.price_n)?,
                price_d: to_u128(&o.price_d)?,
                amount: to_u128(&o.amount)?,
                nonce: to_u64(&o.nonce)?,
                expiry: to_u64(&o.expiry)?,
            })
        })
        .collect()
}

fn build_sample_orders() -> Vec<OrderNative> {
    // Mirror the sample used elsewhere
    let buyer = [0u8; 20]; // placeholder makes deterministic ids for demo; not used for on-chain
    let seller = [1u8; 20];
    let base = [0xAA; 32];
    let quote = [0xBB; 32];
    vec![
        OrderNative { maker: buyer, base, quote, side: Side::Buy, price_n: 3, price_d: 1, amount: 10, nonce: 100, expiry: u64::MAX },
        OrderNative { maker: seller, base, quote, side: Side::Sell, price_n: 2, price_d: 1, amount: 10, nonce: 200, expiry: u64::MAX },
    ]
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CancelTemplateItem { order_id: String, canceled: bool }

fn main() -> Result<()> {
    let args = Args::parse();
    if !args.sample && args.file.is_none() { bail!("provide either --sample or --file <path>"); }

    let orders: Vec<OrderNative> = if args.sample {
        build_sample_orders()
    } else {
        let file = args.file.as_ref().unwrap();
        let data = std::fs::read_to_string(file).with_context(|| format!("reading {}", file))?;
        let json: JsonInput = serde_json::from_str(&data).context("parsing JSON input")?;
        json_to_orders(json)?
    };

    let mut items: Vec<CancelTemplateItem> = Vec::with_capacity(orders.len());
    for o in &orders {
        let oid = order_struct_hash(o);
        items.push(CancelTemplateItem { order_id: format!("0x{}", hex::encode(oid)), canceled: false });
    }
    let s = if args.pretty { serde_json::to_string_pretty(&items)? } else { serde_json::to_string(&items)? };
    if let Some(path) = args.out { std::fs::write(&path, s).with_context(|| format!("writing {}", path))?; } else { println!("{}", s); }
    Ok(())
}
