use defi_lib::defi::{verify_settlement, Balance, Delta, Domain, MatchFill, Order, SettlementInput, Side};
use k256::ecdsa::{signature::DigestSigner, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

type Address = [u8; 20];
type Asset = [u8; 32];

fn addr_from_signer(sk: &SigningKey) -> Address {
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

fn filled_leaf(order_hash: [u8; 32], amount: u128) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(order_hash);
    h.update(&amount.to_be_bytes());
    let out = h.finalize();
    let mut leaf = [0u8; 32];
    leaf.copy_from_slice(&out);
    leaf
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

fn merkle_root_sorted(mut hashes: Vec<[u8; 32]>) -> [u8; 32] {
    if hashes.is_empty() {
        let mut zero = [0u8; 32];
        zero.copy_from_slice(&Keccak256::digest([]));
        return zero;
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
    // Compute prev_filled_root by sorting leaves by order hash
    let buy_hash = order_struct_hash(&buy);
    let sell_hash = order_struct_hash(&sell);
    let mut entries = vec![(buy_hash, filled_leaf(buy_hash, 0)), (sell_hash, filled_leaf(sell_hash, 0))];
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let prev_filled_root = merkle_root_sorted(entries.into_iter().map(|(_, l)| l).collect());
    SettlementInput { domain, orders: vec![buy, sell], matches, initial_balances, proposed_deltas, timestamp: 0, prev_filled_root, prev_filled }
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
