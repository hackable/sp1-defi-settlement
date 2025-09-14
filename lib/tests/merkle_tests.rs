use defi_lib::merkle::*;
use sha3::{Digest, Keccak256};

#[test]
fn test_hash_order_leaf_keccak() {
    let id = [0x11u8; 32];
    let expected = keccak(&id);
    assert_eq!(hash_order_leaf(id), expected);
}

#[test]
fn test_merkle_root_from_leaves_two_nodes() {
    let a = keccak(&[1u8]);
    let b = keccak(&[2u8]);
    let root = merkle_root_from_leaves(vec![a, b]);
    assert_eq!(root, fold_sorted_pair(a, b));
}

#[test]
fn test_verify_merkle_proof_sorted_keccak() {
    let a = keccak(&[1u8]);
    let b = keccak(&[2u8]);
    let root = fold_sorted_pair(a, b);
    assert!(verify_merkle_proof_sorted_keccak(a, &[b], root));
    assert!(verify_merkle_proof_sorted_keccak(b, &[a], root));
}

#[test]
fn test_hash_balances_leaf() {
    let owner = [0xAAu8; 20];
    let asset = [0xBBu8; 32];
    let amount = 123u128;
    let leaf = hash_balances_leaf(owner, asset, amount);
    // Basic sanity: different amounts produce different leaves
    let leaf2 = hash_balances_leaf(owner, asset, amount + 1);
    assert_ne!(leaf, leaf2);

    // Manual parity with Solidity's keccak256(abi.encodePacked(owner, asset, uint128(amount)))
    let mut bytes = Vec::with_capacity(20 + 32 + 16);
    bytes.extend_from_slice(&owner);
    bytes.extend_from_slice(&asset);
    bytes.extend_from_slice(&amount.to_be_bytes());
    let mut k = Keccak256::new();
    k.update(&bytes);
    let out = k.finalize();
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&out);
    assert_eq!(leaf, expected);
}

#[test]
fn test_hash_filled_leaf_parity() {
    let order_id = [0x11u8; 32];
    let val: u128 = 42;
    let leaf = hash_filled_leaf(order_id, val);
    // Manual parity with keccak256(orderId || uint128_be(val))
    let mut buf = [0u8; 48];
    buf[..32].copy_from_slice(&order_id);
    buf[32..].copy_from_slice(&val.to_be_bytes());
    let mut k = Keccak256::new();
    k.update(&buf);
    let out = k.finalize();
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&out);
    assert_eq!(leaf, expected);
}

#[test]
fn test_merkle_root_from_unordered_kv() {
    // Two entries with unordered keys must produce the same root as sorted order
    let k1 = keccak(&[1u8]);
    let k2 = keccak(&[2u8]);
    let v1 = keccak(&[10u8]);
    let v2 = keccak(&[20u8]);
    let root_unsorted = merkle_root_from_unordered_kv(vec![(k2, v2), (k1, v1)]);
    let root_sorted = merkle_root_from_unordered_kv(vec![(k1, v1), (k2, v2)]);
    assert_eq!(root_unsorted, root_sorted);
}
