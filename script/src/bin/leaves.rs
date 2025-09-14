//! Build final balances leaves and Merkle root from a SettlementInput JSON, validating via the library.

use anyhow::{bail, Context, Result};
use clap::Parser;
use defi_lib::defi::{compute_final_entries, Balance, Delta, Domain, MatchFill, Order, SettlementInput, Side};
use serde::Deserialize;
use sha3::{Digest, Keccak256};
use k256::ecdsa::{signature::DigestSigner, Signature, SigningKey, VerifyingKey};

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
#[derive(Deserialize)]
struct JsonDomain { chain_id: String, exchange: String }

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
    pubkey_x: String,
    pubkey_y: String,
    v: u8,
    r: String,
    s: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonMatch { buy_idx: u32, sell_idx: u32, base_filled: String, quote_paid: String }

#[derive(Deserialize)]
struct JsonBalance { owner: String, asset: String, amount: String }

#[derive(Deserialize)]
struct JsonDelta { owner: String, asset: String, delta: String }

#[derive(Deserialize)]
struct JsonInput {
    domain: JsonDomain,
    orders: Vec<JsonOrder>,
    matches: Vec<JsonMatch>,
    initial_balances: Vec<JsonBalance>,
    proposed_deltas: Vec<JsonDelta>,
    timestamp: String,
}

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
fn to_i128(s: &str) -> Result<i128> { s.parse().context("invalid i128") }

fn to_side(s: &str) -> Result<defi_lib::defi::Side> {
    match s { "Buy" | "buy" => Ok(defi_lib::defi::Side::Buy), "Sell" | "sell" => Ok(defi_lib::defi::Side::Sell), _ => bail!("invalid side") }
}

fn order_to_native(j: JsonOrder) -> Result<defi_lib::defi::Order> {
    Ok(defi_lib::defi::Order {
        maker: parse_hex(&j.maker)?,
        base: parse_hex(&j.base)?,
        quote: parse_hex(&j.quote)?,
        side: to_side(&j.side)?,
        price_n: to_u128(&j.price_n)?,
        price_d: to_u128(&j.price_d)?,
        amount: to_u128(&j.amount)?,
        nonce: to_u64(&j.nonce)?,
        expiry: to_u64(&j.expiry)?,
        pubkey_x: parse_hex(&j.pubkey_x)?,
        pubkey_y: parse_hex(&j.pubkey_y)?,
        v: j.v,
        r: parse_hex(&j.r)?,
        s: parse_hex(&j.s)?,
    })
}

fn input_to_native(j: JsonInput) -> Result<SettlementInput> {
    use defi_lib::defi::{Balance, Delta, Domain, MatchFill, SettlementInput};
    let domain = Domain { chain_id: to_u64(&j.domain.chain_id)?, exchange: parse_hex(&j.domain.exchange)? };
    let orders = j.orders.into_iter().map(order_to_native).collect::<Result<Vec<_>>>()?;
    let matches = j.matches.into_iter().map(|m| -> Result<MatchFill> {
        Ok(MatchFill { buy_idx: m.buy_idx, sell_idx: m.sell_idx, base_filled: to_u128(&m.base_filled)?, quote_paid: to_u128(&m.quote_paid)? })
    }).collect::<Result<Vec<_>>>()?;
    let initial_balances = j.initial_balances.into_iter().map(|b| -> Result<Balance> {
        Ok(Balance { owner: parse_hex(&b.owner)?, asset: parse_hex(&b.asset)?, amount: to_u128(&b.amount)? })
    }).collect::<Result<Vec<_>>>()?;
    let proposed_deltas = j.proposed_deltas.into_iter().map(|d| -> Result<Delta> {
        Ok(Delta { owner: parse_hex(&d.owner)?, asset: parse_hex(&d.asset)?, delta: to_i128(&d.delta)? })
    }).collect::<Result<Vec<_>>>()?;
    // Default prev_filled_root to empty and prev_filled to zeros; callers can override by providing a richer JSON
    let prev_filled = vec![0u128; orders.len()];
    let mut prev_filled_root = [0u8; 32];
    prev_filled_root.copy_from_slice(&Keccak256::digest([]));
    // For optimized path, compute orders_root and leave touched empty (this CLI focuses on balances).
    let order_ids: Vec<[u8; 32]> = orders.iter().map(|o| order_struct_hash(o)).collect();
    let orders_root = orders_root_from_list(&order_ids);
    // Compute cancellations_root as parallel tree with value=0 for all orders by default.
    let zero_vals: Vec<u128> = vec![0u128; orders.len()];
    let cancellations_root = filled_root_from_list(&orders.iter().collect::<Vec<_>>(), &zero_vals);
    Ok(SettlementInput { domain, orders, matches, initial_balances, proposed_deltas, timestamp: to_u64(&j.timestamp)?, prev_filled_root, prev_filled, cancellations_root, orders_root, touched: vec![] })
}

fn leaf_hash(owner: Address, asset: Asset, amount: u128) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(owner);
    h.update(asset);
    h.update(&amount.to_be_bytes());
    let out = h.finalize();
    let mut leaf = [0u8; 32];
    leaf.copy_from_slice(&out);
    leaf
}

fn merkle_root_sorted(mut hashes: Vec<[u8; 32]>) -> [u8; 32] {
    if hashes.is_empty() {
        let mut root = [0u8; 32];
        root.copy_from_slice(&Keccak256::digest([]));
        return root;
    }
    while hashes.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity((hashes.len() + 1) / 2);
        let mut i = 0;
        while i < hashes.len() {
            if i + 1 < hashes.len() {
                let a = hashes[i];
                let b = hashes[i + 1];
                let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
                let mut h = Keccak256::new();
                h.update(lo);
                h.update(hi);
                let out = h.finalize();
                let mut parent = [0u8; 32];
                parent.copy_from_slice(&out);
                next.push(parent);
                i += 2;
            } else {
                next.push(hashes[i]);
                i += 1;
            }
        }
        hashes = next;
    }
    hashes[0]
}

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
        build_sample_input()
    } else {
        let file = args.file.as_ref().unwrap();
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
    let root = merkle_root_sorted(hashes);

    let out = Output { root: format!("0x{}", hex::encode(root)), match_count: native_in.matches.len() as u32, leaves: leaves_vec };
    let s = if args.pretty { serde_json::to_string_pretty(&out) } else { serde_json::to_string(&out) }?;

    if let Some(path) = args.out {
        std::fs::write(&path, s).with_context(|| format!("writing {}", path))?;
    } else {
        println!("{}", s);
    }
    Ok(())
}

fn orders_root_from_list(order_ids: &[[u8; 32]]) -> [u8; 32] {
    let entries: Vec<([u8; 32], [u8; 32])> = order_ids
        .iter()
        .map(|oid| (*oid, defi_lib::merkle::hash_order_leaf(*oid)))
        .collect();
    defi_lib::merkle::merkle_root_from_unordered_kv(entries)
}

fn filled_root_from_list(orders: &[&Order], amounts: &[u128]) -> [u8; 32] {
    let entries: Vec<([u8; 32], [u8; 32])> = orders
        .iter()
        .enumerate()
        .map(|(i, o)| {
            let oid = order_struct_hash(o);
            (oid, defi_lib::merkle::hash_filled_leaf(oid, amounts[i]))
        })
        .collect();
    defi_lib::merkle::merkle_root_from_unordered_kv(entries)
}

// ===== Sample input (same as in docs/tests) =====
fn addr_from_signer(sk: &SigningKey) -> [u8; 20] {
    let vk = *sk.verifying_key();
    let pub_uncompressed = vk.to_encoded_point(false);
    let bytes = pub_uncompressed.as_bytes();
    let mut keccak = Keccak256::new();
    keccak.update(&bytes[1..]);
    let out = keccak.finalize();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&out[12..]);
    addr
}

fn pubkey_x(sk: &SigningKey) -> [u8; 32] {
    let vk: VerifyingKey = *sk.verifying_key();
    let pub_uncompressed = vk.to_encoded_point(false);
    let bytes = pub_uncompressed.as_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[1..33]);
    out
}

fn pubkey_y(sk: &SigningKey) -> [u8; 32] {
    let vk: VerifyingKey = *sk.verifying_key();
    let pub_uncompressed = vk.to_encoded_point(false);
    let bytes = pub_uncompressed.as_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[33..]);
    out
}

fn eip712_domain_separator(domain: &Domain) -> [u8; 32] {
    let mut keccak = Keccak256::new();
    keccak.update(b"EIP712Domain(uint256 chainId,address verifyingContract)");
    let typehash = keccak.finalize();

    let mut e = Keccak256::new();
    e.update(&typehash);
    let mut buf = [0u8; 32];
    buf[24..].copy_from_slice(&domain.chain_id.to_be_bytes());
    e.update(&buf);
    let mut abuf = [0u8; 32];
    abuf[12..].copy_from_slice(&domain.exchange);
    e.update(&abuf);
    let out = e.finalize();
    let mut sep = [0u8; 32];
    sep.copy_from_slice(&out);
    sep
}

fn order_struct_hash(order: &Order) -> [u8; 32] {
    let mut keccak = Keccak256::new();
    keccak.update(b"Order(address maker,bytes32 base,bytes32 quote,uint8 side,uint128 price_n,uint128 price_d,uint128 amount,uint64 nonce,uint64 expiry)");
    let typehash = keccak.finalize();

    let mut e = Keccak256::new();
    e.update(&typehash);
    let mut maker_buf = [0u8; 32];
    maker_buf[12..].copy_from_slice(&order.maker);
    e.update(&maker_buf);
    e.update(&order.base);
    e.update(&order.quote);
    let mut side_buf = [0u8; 32];
    side_buf[31] = match order.side { Side::Buy => 0, Side::Sell => 1 };
    e.update(&side_buf);
    let mut u128buf = [0u8; 32];
    u128buf[16..].copy_from_slice(&order.price_n.to_be_bytes());
    e.update(&u128buf);
    u128buf[16..].copy_from_slice(&order.price_d.to_be_bytes());
    e.update(&u128buf);
    u128buf[16..].copy_from_slice(&order.amount.to_be_bytes());
    e.update(&u128buf);
    let mut u64buf = [0u8; 32];
    u64buf[24..].copy_from_slice(&order.nonce.to_be_bytes());
    e.update(&u64buf);
    u64buf[24..].copy_from_slice(&order.expiry.to_be_bytes());
    e.update(&u64buf);
    let out = e.finalize();
    let mut sh = [0u8; 32];
    sh.copy_from_slice(&out);
    sh
}

fn sign_order(order: &Order, domain: &Domain, sk: &SigningKey) -> (u8, [u8; 32], [u8; 32]) {
    let domain_sep = eip712_domain_separator(domain);
    let struct_hash = order_struct_hash(order);
    let mut hasher = Keccak256::new();
    hasher.update(&[0x19, 0x01]);
    hasher.update(&domain_sep);
    hasher.update(&struct_hash);
    let sig: Signature = sk.sign_digest(hasher);
    let bytes = sig.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&bytes[..32]);
    s.copy_from_slice(&bytes[32..]);
    (27, r, s)
}

fn build_sample_input() -> SettlementInput {
    let domain = Domain { chain_id: 1, exchange: [0x11; 20] };
    let buy_sk = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
    let sell_sk = SigningKey::from_bytes((&[2u8; 32]).into()).unwrap();
    let buyer = addr_from_signer(&buy_sk);
    let seller = addr_from_signer(&sell_sk);
    let base: Asset = [0xAA; 32];
    let quote: Asset = [0xBB; 32];

    let mut buy = Order {
        maker: buyer,
        base,
        quote,
        side: Side::Buy,
        price_n: 3,
        price_d: 1,
        amount: 10,
        nonce: 100,
        expiry: u64::MAX,
        pubkey_x: pubkey_x(&buy_sk),
        pubkey_y: pubkey_y(&buy_sk),
        v: 0,
        r: [0u8; 32],
        s: [0u8; 32],
    };
    let mut sell = Order {
        maker: seller,
        base,
        quote,
        side: Side::Sell,
        price_n: 2,
        price_d: 1,
        amount: 10,
        nonce: 200,
        expiry: u64::MAX,
        pubkey_x: pubkey_x(&sell_sk),
        pubkey_y: pubkey_y(&sell_sk),
        v: 0,
        r: [0u8; 32],
        s: [0u8; 32],
    };

    let (_v_b, r_b, s_b) = sign_order(&buy, &domain, &buy_sk);
    buy.v = _v_b; buy.r = r_b; buy.s = s_b;
    let (_v_s, r_s, s_s) = sign_order(&sell, &domain, &sell_sk);
    sell.v = _v_s; sell.r = r_s; sell.s = s_s;

    let matches = vec![MatchFill { buy_idx: 0, sell_idx: 1, base_filled: 5, quote_paid: 10 }];
    let initial_balances = vec![
        Balance { owner: buyer, asset: base, amount: 0 },
        Balance { owner: buyer, asset: quote, amount: 100 },
        Balance { owner: seller, asset: base, amount: 100 },
        Balance { owner: seller, asset: quote, amount: 0 },
    ];
    let proposed_deltas = vec![
        Delta { owner: buyer, asset: base, delta: 5 },
        Delta { owner: buyer, asset: quote, delta: -10 },
        Delta { owner: seller, asset: base, delta: -5 },
        Delta { owner: seller, asset: quote, delta: 10 },
    ];

    let prev_filled = vec![0u128, 0u128];
    let mut prev_filled_root = [0u8; 32];
    prev_filled_root.copy_from_slice(&Keccak256::digest([]));
    let order_ids = vec![order_struct_hash(&buy), order_struct_hash(&sell)];
    let orders_root = orders_root_from_list(&order_ids);
    let cancellations_root = orders_root;
    SettlementInput { domain, orders: vec![buy, sell], matches, initial_balances, proposed_deltas, timestamp: 0, prev_filled_root, prev_filled, cancellations_root, orders_root, touched: vec![] }
}
