use defi_lib::defi::{
    verify_settlement, Balance, Delta, Domain, MatchFill, Order, SettlementInput, Side,
    order_struct_hash, sign_order, addr_from_signer,
};
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use defi_lib::merkle::{hash_order_leaf, hash_filled_leaf};

type Address = [u8; 20];
type Asset = [u8; 32];

fn filled_leaf(order_hash: [u8; 32], amount: u128) -> [u8; 32] { hash_filled_leaf(order_hash, amount) }

use defi_lib::merkle::merkle_root_from_leaves as merkle_root_sorted;

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
        v: 0,
        r: [0u8; 32],
        s: [0u8; 32],
    };

    let (_v_b, r_b, s_b) = sign_order(&buy, &domain, &buy_sk).unwrap();
    buy.v = _v_b; buy.r = r_b; buy.s = s_b;
    let (_v_s, r_s, s_s) = sign_order(&sell, &domain, &sell_sk).unwrap();
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
    // Compute prev_filled_root and orders_root and touched proofs (2-leaf trivial proofs)
    let buy_hash = order_struct_hash(&buy);
    let sell_hash = order_struct_hash(&sell);
    let mut entries = vec![(buy_hash, filled_leaf(buy_hash, 0)), (sell_hash, filled_leaf(sell_hash, 0))];
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let prev_filled_root = merkle_root_sorted(entries.iter().map(|(_, l)| *l).collect());
    let orders_root = merkle_root_sorted(vec![hash_order_leaf(buy_hash), hash_order_leaf(sell_hash)]);
    // cancellations_root: both orders not canceled (value=0), same encoding as filled leaf with value 0
    let cancellations_root = merkle_root_sorted(vec![filled_leaf(buy_hash, 0), filled_leaf(sell_hash, 0)]);
    // Proofs: sibling leaf
    let filled_proof_buy = vec![filled_leaf(sell_hash, 0)];
    let filled_proof_sell = vec![filled_leaf(buy_hash, 0)];
    let orders_proof_buy = vec![hash_order_leaf(sell_hash)];
    let orders_proof_sell = vec![hash_order_leaf(buy_hash)];
    let touched = vec![
        defi_lib::defi::TouchedProof { order_index: 0, order_id: buy_hash, prev_filled: 0, filled_proof: filled_proof_buy.clone(), orders_proof: orders_proof_buy.clone(), cancel_proof: filled_proof_buy },
        defi_lib::defi::TouchedProof { order_index: 1, order_id: sell_hash, prev_filled: 0, filled_proof: filled_proof_sell.clone(), orders_proof: orders_proof_sell.clone(), cancel_proof: filled_proof_sell },
    ];
    SettlementInput { domain, orders: vec![buy, sell], matches, initial_balances, proposed_deltas, timestamp: 0, prev_filled_root, prev_filled, cancellations_root, orders_root, touched }
}

#[test]
fn test_successful_settlement_and_merkle_root() {
    let input = build_sample_input();
    let out = verify_settlement(&input).expect("verification should succeed");
    assert_eq!(out.match_count, 1);

    // Compute expected cumulative_owed root: start from initial (treated as prior cumulative),
    // add only positive deltas.
    let buyer = input.orders[0].maker;
    let seller = input.orders[1].maker;
    let base = input.orders[0].base;
    let quote = input.orders[0].quote;

    let buyer_base_cum = 0u128 + 5u128;   // +5
    let buyer_quote_cum = 100u128 + 0u128; // -10 ignored for cum
    let seller_base_cum = 100u128 + 0u128; // -5 ignored for cum
    let seller_quote_cum = 0u128 + 10u128; // +10

    let leaves = vec![
        leaf_hash(buyer, base, buyer_base_cum),
        leaf_hash(buyer, quote, buyer_quote_cum),
        leaf_hash(seller, base, seller_base_cum),
        leaf_hash(seller, quote, seller_quote_cum),
    ];
    let expected_root = merkle_root_sorted(leaves);
    assert_eq!(out.balances_root, expected_root);

    // Check filledRoot: both buy and sell order cumulative filled = prev(0) + 5, sorted by orderId.
    let buy_hash = order_struct_hash(&input.orders[0]);
    let sell_hash = order_struct_hash(&input.orders[1]);
    let mut fr = vec![(buy_hash, filled_leaf(buy_hash, 5)), (sell_hash, filled_leaf(sell_hash, 5))];
    fr.sort_by(|a, b| a.0.cmp(&b.0));
    let expected_filled_root = merkle_root_sorted(fr.into_iter().map(|(_, l)| l).collect());
    assert_eq!(out.filled_root, expected_filled_root);
}

#[test]
fn test_invalid_signature_rejected() {
    let mut input = build_sample_input();
    // Corrupt r
    input.orders[0].r = [0u8; 32];
    let err = verify_settlement(&input).unwrap_err();
    assert!(err.contains("invalid signature") || err.contains("signature"));
}

#[test]
fn test_price_violation_rejected() {
    let mut input = build_sample_input();
    // Buyer limit 3/1; set effective price 4/1 by making quote_paid too high for same base
    input.matches[0].quote_paid = 20; // base=5 => eff=4
    let err = verify_settlement(&input).unwrap_err();
    assert!(err.contains("buyer") || err.contains("violates"));
}

#[test]
fn test_overfill_rejected() {
    let mut input = build_sample_input();
    input.matches[0].base_filled = 11; // exceeds amount 10
    let err = verify_settlement(&input).unwrap_err();
    assert!(err.contains("overfills"));
}

#[test]
fn test_delta_mismatch_rejected() {
    let mut input = build_sample_input();
    // Break a delta
    input.proposed_deltas[0].delta = 4; // should be 5
    let err = verify_settlement(&input).unwrap_err();
    assert!(err.contains("proposed delta"));
}

#[test]
fn test_negative_balance_rejected() {
    let mut input = build_sample_input();
    // Make buyer quote too low to pay 10
    let buyer = input.orders[0].maker;
    let quote = input.orders[0].quote;
    for b in &mut input.initial_balances {
        if b.owner == buyer && b.asset == quote { b.amount = 5; }
    }
    let err = verify_settlement(&input).unwrap_err();
    assert!(err.contains("negative final balance"));
}

#[test]
fn test_cross_batch_overfill_rejected() {
    let mut input = build_sample_input();
    // Set previous filled close to amount, and try to overfill this batch.
    input.prev_filled = vec![8u128, 0u128]; // buy order amount=10, prev=8
    // Recompute prev_filled_root accordingly
    let buy_hash = order_struct_hash(&input.orders[0]);
    let sell_hash = order_struct_hash(&input.orders[1]);
    let leaves = vec![
        filled_leaf(buy_hash, 8),
        filled_leaf(sell_hash, 0),
    ];
    let prev_root = merkle_root_sorted(leaves);
    input.prev_filled_root = prev_root;
    // This batch tries to fill 5 -> 8 + 5 > 10
    input.matches[0].base_filled = 5;
    let err = verify_settlement(&input).unwrap_err();
    assert!(err.contains("prev_filled") || err.contains("overfills") || err.contains("exceeds"));
}

#[test]
fn test_canceled_order_rejected() {
    // Build the standard sample, then mark the buy order as canceled in cancellations_root.
    let mut input = build_sample_input();
    let buy_hash = order_struct_hash(&input.orders[0]);
    let sell_hash = order_struct_hash(&input.orders[1]);
    // cancellations_root: buy canceled (1), sell not canceled (0)
    let leaves = vec![
        filled_leaf(buy_hash, 1),
        filled_leaf(sell_hash, 0),
    ];
    let new_cancellations_root = merkle_root_sorted(leaves);
    input.cancellations_root = new_cancellations_root;
    // Keep existing cancel_proof values from build_sample_input() which prove value=0 for both orders.
    // Now that the root encodes buy as canceled (1), the guest should reject due to cancel proof failure.
    let err = verify_settlement(&input).unwrap_err();
    assert!(err.contains("cancellationsRoot") || err.contains("cancel") || err.contains("proof"));
}

#[test]
fn test_ghost_touched_rejected() {
    // Start from a valid sample, then remove all matches but keep touched proofs.
    let mut input = build_sample_input();
    input.matches.clear();
    input.proposed_deltas.clear();
    let err = verify_settlement(&input).unwrap_err();
    assert!(err.contains("touched order") || err.contains("not matched") || err.contains("touched"));
}

#[test]
fn test_touched_limit_rejected() {
    // Build a minimal input but exceed touched limit (checked first in verify_settlement)
    let domain = Domain { chain_id: 1, exchange: [0x11; 20] };
    let input = SettlementInput {
        domain,
        orders: vec![],
        matches: vec![],
        initial_balances: vec![],
        proposed_deltas: vec![],
        timestamp: 0,
        prev_filled_root: [0u8; 32],
        prev_filled: vec![],
        cancellations_root: [0u8; 32],
        orders_root: [0u8; 32],
        touched: (0..1001).map(|_| defi_lib::defi::TouchedProof {
            order_index: 0,
            order_id: [0u8; 32],
            prev_filled: 0,
            filled_proof: vec![],
            orders_proof: vec![],
            cancel_proof: vec![],
        }).collect(),
    };
    let err = verify_settlement(&input).unwrap_err();
    assert!(err.contains("touched orders limit") || err.contains("exceeded maximum touched orders limit"));
}

#[test]
fn test_price_multiplication_overflow_rejected() {
    // Construct two orders with huge price_n and base_filled to trigger checked_mul overflow in price check
    let domain = Domain { chain_id: 1, exchange: [0x11; 20] };
    let buy_sk = SigningKey::from_bytes((&[3u8; 32]).into()).unwrap();
    let sell_sk = SigningKey::from_bytes((&[4u8; 32]).into()).unwrap();
    let buyer = addr_from_signer(&buy_sk);
    let seller = addr_from_signer(&sell_sk);
    let base: Asset = [0xCC; 32];
    let quote: Asset = [0xDD; 32];
    let mut buy = Order { maker: buyer, base, quote, side: Side::Buy, price_n: u128::MAX, price_d: 1, amount: u128::MAX, nonce: 1, expiry: u64::MAX, v: 0, r: [0u8; 32], s: [0u8; 32] };
    let mut sell = Order { maker: seller, base, quote, side: Side::Sell, price_n: 1, price_d: 1, amount: u128::MAX, nonce: 2, expiry: u64::MAX, v: 0, r: [0u8; 32], s: [0u8; 32] };
    let (vb, rb, sb) = sign_order(&buy, &domain, &buy_sk).unwrap();
    buy.v = vb; buy.r = rb; buy.s = sb;
    let (vs, rs, ss) = sign_order(&sell, &domain, &sell_sk).unwrap();
    sell.v = vs; sell.r = rs; sell.s = ss;
    let matches = vec![MatchFill { buy_idx: 0, sell_idx: 1, base_filled: u128::MAX, quote_paid: 1 }];
    let input = SettlementInput {
        domain,
        orders: vec![buy, sell],
        matches,
        initial_balances: vec![],
        proposed_deltas: vec![],
        timestamp: 0,
        prev_filled_root: [0u8; 32],
        prev_filled: vec![0, 0],
        cancellations_root: [0u8; 32],
        orders_root: [0u8; 32],
        touched: vec![],
    };
    let err = defi_lib::defi::compute_final_entries(&input).unwrap_err();
    assert!(err.contains("price multiplication overflow"));
}

#[test]
fn test_cumulative_owed_overflow_rejected() {
    // Force cumulative owed overflow by setting initial balance at u128::MAX and positive delta
    let domain = Domain { chain_id: 1, exchange: [0x11; 20] };
    let buy_sk = SigningKey::from_bytes((&[5u8; 32]).into()).unwrap();
    let sell_sk = SigningKey::from_bytes((&[6u8; 32]).into()).unwrap();
    let buyer = addr_from_signer(&buy_sk);
    let seller = addr_from_signer(&sell_sk);
    let base: Asset = [0xEE; 32];
    let quote: Asset = [0xFF; 32];
    let mut buy = Order { maker: buyer, base, quote, side: Side::Buy, price_n: 1, price_d: 1, amount: 1, nonce: 1, expiry: u64::MAX, v: 0, r: [0u8; 32], s: [0u8; 32] };
    let mut sell = Order { maker: seller, base, quote, side: Side::Sell, price_n: 1, price_d: 1, amount: 1, nonce: 2, expiry: u64::MAX, v: 0, r: [0u8; 32], s: [0u8; 32] };
    let (vb, rb, sb) = sign_order(&buy, &domain, &buy_sk).unwrap();
    buy.v = vb; buy.r = rb; buy.s = sb;
    let (vs, rs, ss) = sign_order(&sell, &domain, &sell_sk).unwrap();
    sell.v = vs; sell.r = rs; sell.s = ss;
    let matches = vec![MatchFill { buy_idx: 0, sell_idx: 1, base_filled: 1, quote_paid: 1 }];
    let initial_balances = vec![
        Balance { owner: seller, asset: quote, amount: u128::MAX }, // will overflow when adding +1
    ];
    let input = SettlementInput {
        domain,
        orders: vec![buy, sell],
        matches,
        initial_balances,
        proposed_deltas: vec![],
        timestamp: 0,
        prev_filled_root: [0u8; 32],
        prev_filled: vec![0, 0],
        cancellations_root: [0u8; 32],
        orders_root: [0u8; 32],
        touched: vec![],
    };
    assert!(defi_lib::defi::compute_cumulative_entries(&input).is_err());
}
#[test]
fn test_high_s_signature_rejected() {
    // Start from valid sample, then force a high-s signature on buy order.
    let mut input = build_sample_input();
    // secp256k1 half-order + 1 (big-endian)
    let mut s_hi = [0u8; 32];
    s_hi.copy_from_slice(&[
        0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x80,0x00,0x00,0x00,
        0xA2,0xA8,0x91,0x8C,0xA8,0x5B,0xAF,0xE2,
        0x20,0x16,0xD0,0xB9,0x97,0xE4,0xDF,0x61,
    ]);
    input.orders[0].s = s_hi; // r and v remain valid-looking, but s is non-canonical
    let err = verify_settlement(&input).unwrap_err();
    assert!(err.contains("invalid signature") || err.contains("signature"));
}
