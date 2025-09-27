use crate::defi::{addr_from_signer, order_struct_hash, orders_root_from_list, sign_order, Balance, Delta, Domain, MatchFill, Order, SettlementInput, Side, TouchedProof};
use crate::merkle::{hash_order_leaf, hash_filled_leaf, build_merkle_proof_sorted};
use k256::ecdsa::SigningKey;

pub fn build_sample_input() -> Result<SettlementInput, String> {
    build_sample_input_with_orders(2)
}

pub fn build_sample_input_with_orders(num_orders: usize) -> Result<SettlementInput, String> {
    if num_orders < 2 {
        return Err("Need at least 2 orders for matching".to_string());
    }
    if num_orders % 2 != 0 {
        return Err("Number of orders must be even (half buy, half sell)".to_string());
    }
    let domain = Domain { chain_id: 1, exchange: [0x11; 20] };
    let base = [0xAA; 32];
    let quote = [0xBB; 32];

    let num_pairs = num_orders / 2;
    let mut orders: Vec<Order> = Vec::new();
    let mut matches: Vec<MatchFill> = Vec::new();
    let mut initial_balances: Vec<Balance> = Vec::new();
    let mut proposed_deltas: Vec<Delta> = Vec::new();
    let mut prev_filled: Vec<u128> = Vec::new();
    let mut order_ids: Vec<[u8; 32]> = Vec::new();

    // Generate buy/sell pairs
    fn deterministic_key(seed: u64) -> Result<SigningKey, String> {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&seed.to_be_bytes());
        SigningKey::from_bytes((&bytes).into()).map_err(|_| "bad key".to_string())
    }

    for i in 0..num_pairs {
        let buy_sk = deterministic_key((i * 2 + 1) as u64)?;
        let sell_sk = deterministic_key((i * 2 + 2) as u64)?;
        let buy_addr = addr_from_signer(&buy_sk);
        let sell_addr = addr_from_signer(&sell_sk);

        let mut buy = Order {
            maker: buy_addr,
            base,
            quote,
            side: Side::Buy,
            price_n: 3,
            price_d: 1,
            amount: 10 + (i * 2) as u128,
            nonce: 100 + i as u64,
            expiry: u64::MAX,
            v: 0,
            r: [0u8; 32],
            s: [0u8; 32],
        };

        let mut sell = Order {
            maker: sell_addr,
            base,
            quote,
            side: Side::Sell,
            price_n: 2,
            price_d: 1,
            amount: 10 + (i * 2) as u128,
            nonce: 200 + i as u64,
            expiry: u64::MAX,
            v: 0,
            r: [0u8; 32],
            s: [0u8; 32],
        };

        let (vb, rb, sb) = sign_order(&buy, &domain, &buy_sk)?;
        buy.v = vb; buy.r = rb; buy.s = sb;
        let (vs, rs, ss) = sign_order(&sell, &domain, &sell_sk)?;
        sell.v = vs; sell.r = rs; sell.s = ss;

        let buy_idx = (i * 2) as u32;
        let sell_idx = (i * 2 + 1) as u32;
        let base_filled = std::cmp::min(5 + i as u128, buy.amount.min(sell.amount));
        let quote_paid = base_filled * 2;

        matches.push(MatchFill { buy_idx, sell_idx, base_filled, quote_paid });

        // Add balances for this pair
        if initial_balances.iter().find(|b| b.owner == buy_addr && b.asset == quote).is_none() {
            initial_balances.push(Balance { owner: buy_addr, asset: base, amount: 0 });
            initial_balances.push(Balance { owner: buy_addr, asset: quote, amount: 100 + (i * 10) as u128 });
        }
        if initial_balances.iter().find(|b| b.owner == sell_addr && b.asset == base).is_none() {
            initial_balances.push(Balance { owner: sell_addr, asset: base, amount: 100 + (i * 10) as u128 });
            initial_balances.push(Balance { owner: sell_addr, asset: quote, amount: 0 });
        }

        // Add deltas
        proposed_deltas.push(Delta { owner: buy_addr, asset: base, delta: base_filled as i128 });
        proposed_deltas.push(Delta { owner: buy_addr, asset: quote, delta: -(quote_paid as i128) });
        proposed_deltas.push(Delta { owner: sell_addr, asset: base, delta: -(base_filled as i128) });
        proposed_deltas.push(Delta { owner: sell_addr, asset: quote, delta: quote_paid as i128 });

        order_ids.push(order_struct_hash(&buy));
        order_ids.push(order_struct_hash(&sell));
        prev_filled.push(0u128);
        prev_filled.push(0u128);

        orders.push(buy);
        orders.push(sell);
    }

    // Compute orders_root from IDs (library sorts by id)
    let orders_root = orders_root_from_list(&order_ids);
    // Build leaves sorted by order_id to construct proofs
    let mut pairs: Vec<([u8; 32], usize)> = order_ids.iter().copied().zip(0..order_ids.len()).collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let sorted_indices: Vec<usize> = pairs.iter().map(|p| p.1).collect();
    let orders_leaves_sorted: Vec<[u8; 32]> = pairs.iter().map(|(oid, _)| hash_order_leaf(*oid)).collect();
    let mut filled_leaves_sorted: Vec<[u8; 32]> = Vec::with_capacity(pairs.len());
    for (oid, _) in pairs.iter() {
        let orig_idx = order_ids
            .iter()
            .position(|id| id == oid)
            .ok_or_else(|| "order id missing when building filled leaves".to_string())?;
        filled_leaves_sorted.push(hash_filled_leaf(*oid, prev_filled[orig_idx]));
    }

    // Build merkle tree and get root
    let (_, _orders_root_calc) = build_merkle_proof_sorted(orders_leaves_sorted.clone(), 0);
    let (_, prev_filled_root) = build_merkle_proof_sorted(filled_leaves_sorted.clone(), 0);
    let cancellations_root = prev_filled_root;

    // Build touched proofs for all orders
    let mut touched = Vec::new();
    for i in 0..order_ids.len() {
        let sorted_pos = sorted_indices
            .iter()
            .position(|&idx| idx == i)
            .ok_or_else(|| "sorted index missing for touched proof".to_string())?;
        let (orders_proof, _) = build_merkle_proof_sorted(orders_leaves_sorted.clone(), sorted_pos);
        let (filled_proof, _) = build_merkle_proof_sorted(filled_leaves_sorted.clone(), sorted_pos);

        touched.push(TouchedProof {
            order_index: i as u32,
            order_id: order_ids[i],
            prev_filled: prev_filled[i],
            filled_proof: filled_proof.clone(),
            orders_proof,
            cancel_proof: filled_proof,
        });
    };

    Ok(SettlementInput {
        domain,
        orders,
        matches,
        initial_balances,
        proposed_deltas,
        timestamp: 0,
        prev_filled_root,
        prev_filled,
        cancellations_root,
        cancellations_updates: vec![],
        orders_root,
        orders_touched: touched,
    })
}
