use crate::defi::{addr_from_signer, order_struct_hash, orders_root_from_list, sign_order, Balance, Delta, Domain, MatchFill, Order, SettlementInput, Side, TouchedProof};
use crate::merkle::{hash_order_leaf, hash_filled_leaf, build_merkle_proof_sorted};
use k256::ecdsa::SigningKey;

pub fn build_sample_input() -> Result<SettlementInput, String> {
    let domain = Domain { chain_id: 1, exchange: [0x11; 20] };

    let maker_buy_sk = SigningKey::from_bytes((&[1u8; 32]).into()).map_err(|_| "bad key")?;
    let maker_sell_sk = SigningKey::from_bytes((&[2u8; 32]).into()).map_err(|_| "bad key")?;
    let maker_buy_addr = addr_from_signer(&maker_buy_sk);
    let maker_sell_addr = addr_from_signer(&maker_sell_sk);

    let base = [0xAA; 32];
    let quote = [0xBB; 32];

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
        v: 0,
        r: [0u8; 32],
        s: [0u8; 32],
    };
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
        v: 0,
        r: [0u8; 32],
        s: [0u8; 32],
    };

    let (vb, rb, sb) = sign_order(&buy, &domain, &maker_buy_sk)?;
    buy.v = vb; buy.r = rb; buy.s = sb;
    let (vs, rs, ss) = sign_order(&sell, &domain, &maker_sell_sk)?;
    sell.v = vs; sell.r = rs; sell.s = ss;

    let matches = vec![MatchFill { buy_idx: 0, sell_idx: 1, base_filled: 5, quote_paid: 10 }];
    let initial_balances = vec![
        Balance { owner: maker_buy_addr, asset: base, amount: 0 },
        Balance { owner: maker_buy_addr, asset: quote, amount: 100 },
        Balance { owner: maker_sell_addr, asset: base, amount: 100 },
        Balance { owner: maker_sell_addr, asset: quote, amount: 0 },
    ];
    let proposed_deltas = vec![
        Delta { owner: maker_buy_addr, asset: base, delta: 5 },
        Delta { owner: maker_buy_addr, asset: quote, delta: -10 },
        Delta { owner: maker_sell_addr, asset: base, delta: -5 },
        Delta { owner: maker_sell_addr, asset: quote, delta: 10 },
    ];

    let prev_filled = vec![0u128, 0u128];
    let order_ids = vec![order_struct_hash(&buy), order_struct_hash(&sell)];
    // Compute orders_root from IDs (library sorts by id)
    let orders_root = orders_root_from_list(&order_ids);
    // Build leaves sorted by order_id to construct proofs
    let mut pairs: Vec<([u8; 32], usize)> = order_ids.iter().copied().zip(0..order_ids.len()).collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let sorted_indices: Vec<usize> = pairs.iter().map(|p| p.1).collect();
    let orders_leaves_sorted: Vec<[u8; 32]> = pairs.iter().map(|(oid, _)| hash_order_leaf(*oid)).collect();
    let filled_leaves_sorted: Vec<[u8; 32]> = pairs.iter().enumerate().map(|(i, (oid, _))| hash_filled_leaf(*oid, prev_filled[i]))
        .collect();
    // Proofs and roots
    let pos0 = if sorted_indices[0] == 0 { 0 } else { 1 };
    let pos1 = 1 - pos0;
    let (proof_orders_0, orders_root_a) = build_merkle_proof_sorted(orders_leaves_sorted.clone(), pos0);
    let (proof_orders_1, orders_root_b) = build_merkle_proof_sorted(orders_leaves_sorted.clone(), pos1);
    debug_assert_eq!(orders_root_a, orders_root_b);
    let (proof_filled_0, prev_root_a) = build_merkle_proof_sorted(filled_leaves_sorted.clone(), pos0);
    let (proof_filled_1, prev_root_b) = build_merkle_proof_sorted(filled_leaves_sorted, pos1);
    debug_assert_eq!(prev_root_a, prev_root_b);
    let prev_filled_root = prev_root_a;
    // cancellations: all zeros, same encoding as filled leaves with value 0
    let cancellations_root = prev_filled_root;
    // Compose touched proofs covering both matched orders (index 0 and 1 in input order)
    let touched = vec![
        TouchedProof {
            order_index: 0,
            order_id: order_ids[0],
            prev_filled: prev_filled[0],
            filled_proof: proof_filled_0.clone(),
            orders_proof: proof_orders_0,
            cancel_proof: proof_filled_0.clone(),
        },
        TouchedProof {
            order_index: 1,
            order_id: order_ids[1],
            prev_filled: prev_filled[1],
            filled_proof: proof_filled_1.clone(),
            orders_proof: proof_orders_1,
            cancel_proof: proof_filled_1,
        },
    ];

    Ok(SettlementInput {
        domain,
        orders: vec![buy, sell],
        matches,
        initial_balances,
        proposed_deltas,
        timestamp: 0,
        prev_filled_root,
        prev_filled,
        cancellations_root,
        orders_root,
        touched,
    })
}
