//! Generate a Merkle proof for (owner, asset) from a JSON leaves file.
//! Leaf = keccak256(owner(20) || asset(32) || amount_be16). Tree uses sorted-pair keccak.

use clap::Parser;
use serde::Deserialize;
use sha3::{Digest, Keccak256};

#[derive(Parser, Debug)]
#[command(author, version, about = "Generate Merkle proof for balances root", long_about = None)]
struct Args {
    /// Path to JSON file containing leaves (array or {"leaves": [...]})
    #[arg(long, short = 'f')]
    file: String,

    /// 0x-prefixed hex address (20 bytes)
    #[arg(long)]
    owner: String,

    /// 0x-prefixed hex bytes32 (32 bytes)
    #[arg(long)]
    asset: String,

    /// Pretty-print JSON output
    #[arg(long, default_value_t = false)]
    pretty: bool,
}

#[derive(Deserialize)]
struct LeafJson {
    owner: String,
    asset: String,
    amount: String,
}

type Address = [u8; 20];
type Asset = [u8; 32];

fn parse_hex<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let ss = s.strip_prefix("0x").ok_or("missing 0x prefix")?;
    if ss.len() != N * 2 {
        return Err(format!("expected {} hex chars, got {}", N * 2, ss.len()));
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(ss, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
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

fn merkle_proof_sorted(leaves: Vec<[u8; 32]>, mut idx: usize) -> (Vec<[u8; 32]>, [u8; 32]) {
    if leaves.is_empty() {
        let mut root = [0u8; 32];
        root.copy_from_slice(&Keccak256::digest([]));
        return (vec![], root);
    }
    let mut proof = Vec::new();
    let mut level = leaves;
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0usize;
        while i < level.len() {
            if i + 1 < level.len() {
                let a = level[i];
                let b = level[i + 1];
                // If our index is in this pair, record sibling.
                if idx == i {
                    proof.push(b);
                } else if idx == i + 1 {
                    proof.push(a);
                }
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
                // Promote odd without sibling
                next.push(level[i]);
                i += 1;
            }
        }
        // Move to next level index
        idx /= 2;
        level = next;
    }
    (proof, level[0])
}

fn main() -> Result<(), String> {
    let args = Args::parse();

    // Load leaves JSON (array or object with 'leaves')
    let data = std::fs::read_to_string(&args.file).map_err(|e| e.to_string())?;
    let value: serde_json::Value = serde_json::from_str(&data).map_err(|e| e.to_string())?;
    let leaves_val = if value.is_array() {
        value
    } else if value.is_object() {
        value.get("leaves").cloned().ok_or("expected top-level array or {\"leaves\": [...]} ")?
    } else {
        return Err("unsupported JSON format".to_string());
    };

    let leaves_json: Vec<LeafJson> = serde_json::from_value(leaves_val).map_err(|e| e.to_string())?;

    // Parse target
    let target_owner: Address = parse_hex(&args.owner)?;
    let target_asset: Asset = parse_hex(&args.asset)?;

    // Build entries
    let mut entries: Vec<(Address, Asset, u128)> = Vec::with_capacity(leaves_json.len());
    for lj in leaves_json {
        let owner: Address = parse_hex(&lj.owner)?;
        let asset: Asset = parse_hex(&lj.asset)?;
        let amount: u128 = lj.amount.parse().map_err(|_| "invalid amount")?;
        entries.push((owner, asset, amount));
    }

    // Sort by (owner, then asset) to match guest
    entries.sort_by(|a, b| match a.0.cmp(&b.0) { std::cmp::Ordering::Equal => a.1.cmp(&b.1), o => o });

    // Find index and compute leaf hashes
    let mut idx = None;
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(entries.len());
    for (i, (owner, asset, amount)) in entries.iter().copied().enumerate() {
        if owner == target_owner && asset == target_asset { idx = Some(i); }
        leaves.push(leaf_hash(owner, asset, amount));
    }
    let idx = idx.ok_or("target (owner, asset) not found in leaves")?;

    let (proof, root) = merkle_proof_sorted(leaves, idx);
    let amount = entries[idx].2;

    // Output JSON
    #[derive(serde::Serialize)]
    struct Out<'a> { amount: String, root: String, proof: Vec<String>, owner: &'a str, asset: &'a str }
    let out = Out {
        amount: amount.to_string(),
        root: format!("0x{}", hex::encode(root)),
        proof: proof.into_iter().map(|h| format!("0x{}", hex::encode(h))).collect(),
        owner: &args.owner,
        asset: &args.asset,
    };

    let s = if args.pretty { serde_json::to_string_pretty(&out) } else { serde_json::to_string(&out) }
        .map_err(|e| e.to_string())?;
    println!("{}", s);
    Ok(())
}
