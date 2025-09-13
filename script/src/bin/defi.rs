//! Host CLI to execute/prove DeFi settlement verification in SP1.

use alloy_sol_types::SolType;
use clap::Parser;
use defi_lib::defi::{Balance, Delta, Domain, MatchFill, Order, SettlementInput, Side, TouchedProof};
use defi_lib::SettlementPublicValues;
use k256::ecdsa::{signature::DigestSigner, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};
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

fn main() {
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    let args = Args::parse();
    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    let client = ProverClient::from_env();

    // Build input (sample for now)
    let input = if args.sample { build_sample_input() } else { build_sample_input() };

    // Export JSON only if explicitly requested via --export. No default export.
    let mut exported = false;
    if let Some(path) = &args.export {
        if let Err(e) = export_sample_json(&input, path) {
            eprintln!("Warning: failed to write {}: {}", path, e);
        } else {
            println!("Wrote {}", path);
            exported = true;
        }
    }

    if args.export_only {
        if !exported {
            eprintln!("Nothing exported: provide --export <path>.");
        }
        return;
    }

    // Prepare stdin and write the input
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    if args.execute {
        let (output, _report) = client.execute(DEFI_ELF, &stdin).run().unwrap();
        let pv = SettlementPublicValues::abi_decode(output.as_slice()).unwrap();
        println!("matchCount: {}", pv.matchCount);
        println!("balancesRoot: 0x{}", hex::encode(pv.balancesRoot));
        println!("prevFilledRoot: 0x{}", hex::encode(pv.prevFilledRoot));
        println!("filledRoot: 0x{}", hex::encode(pv.filledRoot));
    } else {
        let (pk, vk) = client.setup(DEFI_ELF);
        let proof = client.prove(&pk, &stdin).run().expect("failed to generate proof");
        println!("Successfully generated proof!");
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
        let pv = SettlementPublicValues::abi_decode(proof.public_values.as_slice()).unwrap();
        println!("matchCount: {}", pv.matchCount);
        println!("balancesRoot: 0x{}", hex::encode(pv.balancesRoot));
        println!("prevFilledRoot: 0x{}", hex::encode(pv.prevFilledRoot));
        println!("filledRoot: 0x{}", hex::encode(pv.filledRoot));
    }
}

fn build_sample_input() -> SettlementInput {
    // Domain
    let domain = Domain { chain_id: 1, exchange: [0x11; 20] };

    // Two makers with signer keys
    let maker_buy_sk = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
    let maker_sell_sk = SigningKey::from_bytes((&[2u8; 32]).into()).unwrap();
    let maker_buy_addr = addr_from_signer(&maker_buy_sk);
    let maker_sell_addr = addr_from_signer(&maker_sell_sk);

    let base = [0xAA; 32];
    let quote = [0xBB; 32];

    // Buy order: willing to pay up to price 3/1 quote per base, amount up to 10 base
    let mut buy = Order {
        maker: maker_buy_addr,
        base,
        quote,
        side: Side::Buy,
        price_n: 3,
        price_d: 1,
        amount: 10,
        nonce: 100,
        expiry: u64::MAX,
        pubkey_x: pubkey_x(&maker_buy_sk),
        pubkey_y: pubkey_y(&maker_buy_sk),
        v: 0,
        r: [0u8; 32],
        s: [0u8; 32],
    };

    // Sell order: wants at least price 2/1, amount up to 10 base
    let mut sell = Order {
        maker: maker_sell_addr,
        base,
        quote,
        side: Side::Sell,
        price_n: 2,
        price_d: 1,
        amount: 10,
        nonce: 200,
        expiry: u64::MAX,
        pubkey_x: pubkey_x(&maker_sell_sk),
        pubkey_y: pubkey_y(&maker_sell_sk),
        v: 0,
        r: [0u8; 32],
        s: [0u8; 32],
    };

    // Sign orders (EIP-712 digest; no recovery in guest).
    let (_v_b, r_b, s_b) = sign_order(&buy, &domain, &maker_buy_sk);
    buy.v = _v_b;
    buy.r = r_b;
    buy.s = s_b;
    let (_v_s, r_s, s_s) = sign_order(&sell, &domain, &maker_sell_sk);
    sell.v = _v_s;
    sell.r = r_s;
    sell.s = s_s;

    // One match: trade 5 base at price 2 quote per base => quote=10
    let matches = vec![MatchFill { buy_idx: 0, sell_idx: 1, base_filled: 5, quote_paid: 10 }];

    // Initial balances
    let initial_balances = vec![
        Balance { owner: maker_buy_addr, asset: base, amount: 0 },
        Balance { owner: maker_buy_addr, asset: quote, amount: 100 },
        Balance { owner: maker_sell_addr, asset: base, amount: 100 },
        Balance { owner: maker_sell_addr, asset: quote, amount: 0 },
    ];

    // Proposed deltas computed by host (must match guest checks)
    let proposed_deltas = vec![
        Delta { owner: maker_buy_addr, asset: base, delta: 5 },
        Delta { owner: maker_buy_addr, asset: quote, delta: -10 },
        Delta { owner: maker_sell_addr, asset: base, delta: -5 },
        Delta { owner: maker_sell_addr, asset: quote, delta: 10 },
    ];

    // Previous filled root/counters (assume no prior fills):
    let prev_filled = vec![0u128, 0u128];
    // Compute prev_filled_root and orders_root over both orders (including zeros) to match guest logic.
    let order_ids = vec![order_struct_hash(&buy), order_struct_hash(&sell)];
    let prev_filled_root = filled_root_from_list(&[&buy, &sell], &prev_filled);
    let orders_root = orders_root_from_list(&order_ids);

    // Build simple proofs for 2-leaf trees (sibling is the other leaf) for both orders.
    let orders_leaves: Vec<[u8; 32]> = order_ids.iter().map(|oid| hash_order_leaf(*oid)).collect();
    let filled_leaves: Vec<[u8; 32]> = order_ids
        .iter()
        .zip(prev_filled.iter())
        .map(|(oid, pf)| hash_filled_leaf(*oid, *pf))
        .collect();
    // Sort by order_id to match root building
    let mut pairs: Vec<([u8; 32], usize)> = order_ids.iter().copied().zip(0..order_ids.len()).collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let (first_idx, second_idx) = (pairs[0].1, pairs[1].1);
    // Proof for first is sibling = leaf(second), and vice-versa
    let touched = vec![
        TouchedProof {
            order_index: 0,
            order_id: order_ids[0],
            prev_filled: prev_filled[0],
            filled_proof: vec![filled_leaves[if first_idx == 0 { second_idx } else { first_idx }]],
            orders_proof: vec![orders_leaves[if first_idx == 0 { second_idx } else { first_idx }]],
        },
        TouchedProof {
            order_index: 1,
            order_id: order_ids[1],
            prev_filled: prev_filled[1],
            filled_proof: vec![filled_leaves[if second_idx == 1 { first_idx } else { second_idx }]],
            orders_proof: vec![orders_leaves[if second_idx == 1 { first_idx } else { second_idx }]],
        },
    ];

    SettlementInput {
        domain,
        orders: vec![buy, sell],
        matches,
        initial_balances,
        proposed_deltas,
        timestamp: 0,
        prev_filled_root,
        prev_filled,
        orders_root,
        touched,
    }
}

fn filled_root_from_list(orders: &[&Order], amounts: &[u128]) -> [u8; 32] {
    // Build leaves = keccak(order_struct_hash || amount_be16) sorted by order hash
    let mut entries: Vec<([u8; 32], [u8; 32])> = Vec::with_capacity(orders.len());
    for (i, o) in orders.iter().enumerate() {
        let oid = order_struct_hash(o);
        let mut h = Keccak256::new();
        h.update(oid);
        h.update(&amounts[i].to_be_bytes());
        let out = h.finalize();
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(&out);
        entries.push((oid, leaf));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut level: Vec<[u8; 32]> = entries.into_iter().map(|(_, leaf)| leaf).collect();
    if level.is_empty() {
        let mut r = [0u8; 32];
        r.copy_from_slice(&Keccak256::digest([]));
        return r;
    }
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                let a = level[i];
                let b = level[i + 1];
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
                next.push(level[i]);
                i += 1;
            }
        }
        level = next;
    }
    level[0]
}

fn orders_root_from_list(order_ids: &[[u8; 32]]) -> [u8; 32] {
    if order_ids.is_empty() { return Keccak256::digest([]).into(); }
    let mut leaves: Vec<[u8; 32]> = order_ids.iter().map(|oid| hash_order_leaf(*oid)).collect();
    // sort by order_id ascending to match root builder
    let mut pairs: Vec<([u8; 32], [u8; 32])> = order_ids.iter().copied().zip(leaves.iter().copied()).collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    leaves = pairs.into_iter().map(|(_, leaf)| leaf).collect();
    let mut level = leaves;
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                let a = level[i];
                let b = level[i + 1];
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
                next.push(level[i]);
                i += 1;
            }
        }
        level = next;
    }
    level[0]
}

// ----------------- Export sample input as documented JSON -----------------

fn export_sample_json(input: &SettlementInput, filename: &str) -> Result<(), String> {
    #[derive(serde::Serialize)]
    struct JsonDomain { chain_id: String, exchange: String }
    #[derive(serde::Serialize)]
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
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct JsonMatch { buy_idx: u32, sell_idx: u32, base_filled: String, quote_paid: String }
    #[derive(serde::Serialize)]
    struct JsonBalance { owner: String, asset: String, amount: String }
    #[derive(serde::Serialize)]
    struct JsonDelta { owner: String, asset: String, delta: String }
    #[derive(serde::Serialize)]
    struct JsonInput {
        domain: JsonDomain,
        orders: Vec<JsonOrder>,
        matches: Vec<JsonMatch>,
        initial_balances: Vec<JsonBalance>,
        proposed_deltas: Vec<JsonDelta>,
        timestamp: String,
    }

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
        pubkey_x: hex32(&o.pubkey_x),
        pubkey_y: hex32(&o.pubkey_y),
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

fn sign_order(order: &Order, domain: &Domain, sk: &SigningKey) -> (u8, [u8; 32], [u8; 32]) {
    // EIP-712 digest = keccak256("\x19\x01" || domainSeparator || structHash)
    let domain_sep = eip712_domain_separator(domain);
    let struct_hash = order_struct_hash(order);
    let mut hasher = sha3::Keccak256::new();
    hasher.update(&[0x19, 0x01]);
    hasher.update(&domain_sep);
    hasher.update(&struct_hash);
    let sig: Signature = sk.sign_digest(hasher);
    // Dummy v for compatibility (not used by guest)
    let v: u8 = 27;
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    let sig_bytes = sig.to_bytes();
    r.copy_from_slice(&sig_bytes[..32]);
    s.copy_from_slice(&sig_bytes[32..]);
    (v, r, s)
}

fn eip712_domain_separator(domain: &Domain) -> [u8; 32] {
    // keccak256(abi.encode(
    //   keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"),
    //   chainId, verifyingContract))
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
    // keccak256(abi.encode(
    //   keccak256("Order(address maker,bytes32 base,bytes32 quote,uint8 side,uint128 price_n,uint128 price_d,uint128 amount,uint64 nonce,uint64 expiry)"),
    //   maker, base, quote, side, price_n, price_d, amount, nonce, expiry))
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
fn hash_order_leaf(order_id: [u8; 32]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(order_id);
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

fn hash_filled_leaf(order_id: [u8; 32], cumulative_filled: u128) -> [u8; 32] {
    let mut buf = [0u8; 48];
    buf[..32].copy_from_slice(&order_id);
    buf[32..].copy_from_slice(&cumulative_filled.to_be_bytes());
    let mut h = Keccak256::new();
    h.update(&buf);
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}
