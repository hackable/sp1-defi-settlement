use sha3::{Digest, Keccak256};

pub fn keccak(bytes: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

pub fn fold_sorted_pair(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&lo);
    buf[32..].copy_from_slice(&hi);
    keccak(&buf)
}

pub fn verify_merkle_proof_sorted_keccak(mut leaf: [u8; 32], proof: &[[u8; 32]], root: [u8; 32]) -> bool {
    for sib in proof {
        leaf = fold_sorted_pair(leaf, *sib);
    }
    leaf == root
}

pub fn hash_order_leaf(order_id: [u8; 32]) -> [u8; 32] { keccak(&order_id) }

pub fn hash_filled_leaf(order_id: [u8; 32], value: u128) -> [u8; 32] {
    let mut buf = [0u8; 48];
    buf[..32].copy_from_slice(&order_id);
    buf[32..].copy_from_slice(&value.to_be_bytes());
    keccak(&buf)
}

pub fn hash_balances_leaf(owner: [u8; 20], asset: [u8; 32], amount: u128) -> [u8; 32] {
    let mut buf = Vec::with_capacity(20 + 32 + 16);
    buf.extend_from_slice(&owner);
    buf.extend_from_slice(&asset);
    buf.extend_from_slice(&amount.to_be_bytes());
    keccak(&buf)
}

/// Build a Merkle root from a list of leaves using sorted-pair Keccak parents.
pub fn merkle_root_from_leaves(leaves: Vec<[u8; 32]>) -> [u8; 32] {
    if leaves.is_empty() { return keccak(&[]); }
    let mut level = leaves;
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(fold_sorted_pair(level[i], level[i + 1]));
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

/// Build a Merkle root from unordered (key, leaf) pairs by sorting by key first.
pub fn merkle_root_from_unordered_kv(mut entries: Vec<([u8; 32], [u8; 32])>) -> [u8; 32] {
    if entries.is_empty() { return keccak(&[]); }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let leaves: Vec<[u8; 32]> = entries.into_iter().map(|(_, l)| l).collect();
    merkle_root_from_leaves(leaves)
}
