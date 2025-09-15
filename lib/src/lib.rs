use alloy_sol_types::sol;
use k256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

pub mod merkle;
pub mod util;
pub mod io;
pub mod samples;

// Re-exports for convenience in scripts/tests
pub use merkle::{
    hash_balances_leaf, hash_filled_leaf, hash_order_leaf, merkle_root_from_unordered_kv,
    verify_merkle_proof_sorted_keccak,
};

pub use defi::{
    eip712_domain_separator, order_struct_hash, sign_order, addr_from_signer,
};

pub use util::{parse_hex, to_u128, to_u64, to_i128, to_side};

sol! {
    /// Public values for the DeFi settlement program.
    struct SettlementPublicValues {
        bytes32 balancesRoot;
        bytes32 prevFilledRoot;
        bytes32 filledRoot;
        bytes32 cancellationsRoot;
        // EIP-712 domain separator binding (chainId, exchange)
        bytes32 domainSeparator;
        uint32 matchCount;
    }
}


/// DeFi settlement verification module.
pub mod defi {
    use super::*;
    use crate::merkle::fold_sorted_pair;
    use core::cmp::Ordering;
    use std::collections::BTreeMap;

    pub type Address = [u8; 20];
    pub type Asset = [u8; 32];

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Domain {
        pub chain_id: u64,
        pub exchange: Address,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum Side {
        Buy,  // buy base, pay quote
        Sell, // sell base, receive quote
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Order {
        pub maker: Address,
        pub base: Asset,
        pub quote: Asset,
        pub side: Side,
        pub price_n: u128, // quote per base numerator
        pub price_d: u128, // quote per base denominator (>0)
        pub amount: u128,  // max base amount (Sell) or max base to acquire (Buy)
        pub nonce: u64,
        pub expiry: u64,
        // Ethereum-style signature components
        pub v: u8,
        pub r: [u8; 32],
        pub s: [u8; 32],
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct MatchFill {
        pub buy_idx: u32,
        pub sell_idx: u32,
        pub base_filled: u128, // amount of base that changes hands
        pub quote_paid: u128,   // amount of quote buyer pays
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Balance {
        pub owner: Address,
        pub asset: Asset,
        pub amount: u128,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Delta {
        pub owner: Address,
        pub asset: Asset,
        pub delta: i128,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct SettlementInput {
        pub domain: Domain,
        pub orders: Vec<Order>,
        pub matches: Vec<MatchFill>,
        pub initial_balances: Vec<Balance>,
        pub proposed_deltas: Vec<Delta>,
        pub timestamp: u64,
        // Cumulative filled root from previous state (for binding in public values).
        pub prev_filled_root: [u8; 32],
        // Previous cumulative filled per order (aligned with orders). For now, proofs to prev_filled_root
        // are out of scope; the guest will compute the new root from these values + this batch fills.
        pub prev_filled: Vec<u128>,
        // Cancellations root BEFORE this batch (orderId -> 0/1); 1 means canceled.
        pub cancellations_root: [u8; 32],
        // Optional cancellations updates to apply in this batch via sparse Merkle update.
        pub cancellations_updates: Vec<CancellationUpdate>,
        // Optimized inputs: orders root and per-order proofs for touched orders.
        pub orders_root: [u8; 32],
        pub orders_touched: Vec<TouchedProof>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct TouchedProof {
        pub order_index: u32,
        pub order_id: [u8; 32],
        pub prev_filled: u128,
        pub filled_proof: Vec<[u8; 32]>,
        pub orders_proof: Vec<[u8; 32]>,
        pub cancel_proof: Vec<[u8; 32]>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct CancellationUpdate {
        pub order_id: [u8; 32],
        pub prev_value: u128,
        pub new_value: u128,
        pub proof: Vec<[u8; 32]>,
    }

    #[derive(Clone, Debug)]
    pub struct SettlementOutput {
        pub balances_root: [u8; 32],
        pub prev_filled_root: [u8; 32],
        pub filled_root: [u8; 32],
        pub cancellations_root: [u8; 32],
        pub match_count: u32,
    }

    pub fn verify_settlement(input: &SettlementInput) -> Result<SettlementOutput, String> {
        const MAX_TOUCHED_ORDERS: usize = 1_000;
        if input.orders_touched.len() > MAX_TOUCHED_ORDERS {
            return Err("exceeded maximum touched orders limit".to_string());
        }
        // Verify per-order proofs for all touched orders and ensure coverage of matched indices.
        // Build map: index -> proof
        let mut touched_map = BTreeMap::new();
        for tp in &input.orders_touched {
            if (tp.order_index as usize) >= input.orders.len() {
                return Err("touched order_index out of bounds".to_string());
            }
            // Verify ordersRoot inclusion
            let ord = &input.orders[tp.order_index as usize];
            let oid_calc = order_struct_hash(ord);
            if oid_calc != tp.order_id {
                return Err("touched order_id mismatch".to_string());
            }
            let order_leaf = crate::merkle::hash_order_leaf(tp.order_id);
            if !crate::merkle::verify_merkle_proof_sorted_keccak(order_leaf, &tp.orders_proof, input.orders_root) {
                return Err("ordersRoot inclusion proof failed".to_string());
            }
            // Verify prevFilledRoot inclusion for prev value
            // Prefer provided prev_filled in touched; if a list entry is provided, ensure consistency.
            if let Some(prev_list) = input.prev_filled.get(tp.order_index as usize) {
                if *prev_list != tp.prev_filled {
                    return Err("prev_filled mismatch between list and touched proof".to_string());
                }
            }
            let filled_leaf_prev = crate::merkle::hash_filled_leaf(tp.order_id, tp.prev_filled);
            if !crate::merkle::verify_merkle_proof_sorted_keccak(filled_leaf_prev, &tp.filled_proof, input.prev_filled_root) {
                return Err("prevFilledRoot inclusion proof failed".to_string());
            }
            // cancellations_root value must be 0 (not canceled)
            let cancel_leaf = crate::merkle::hash_filled_leaf(tp.order_id, 0);
            if !crate::merkle::verify_merkle_proof_sorted_keccak(cancel_leaf, &tp.cancel_proof, input.cancellations_root) {
                return Err("cancellationsRoot inclusion proof failed".to_string());
            }
            touched_map.insert(tp.order_index as usize, tp);
        }
        // Ensure all matched order indices are covered by touched proofs.
        for m in &input.matches {
            let bi = m.buy_idx as usize;
            let si = m.sell_idx as usize;
            if !touched_map.contains_key(&bi) || !touched_map.contains_key(&si) {
                return Err("missing touched proof for matched order".to_string());
            }
        }

        // Verify signatures only for touched orders to avoid O(N) signature checks.
        for (idx, _tp) in touched_map.iter() {
            let o = &input.orders[*idx];
            if !verify_order_sig(o, &input.domain) {
                return Err(format!("invalid signature for touched order {}", idx));
            }
        }

        // Perform full validation using snapshot balances logic (non-negativity, limits, deltas),
        // skipping redundant signature verification (already checked for touched orders).
        let _final_entries = compute_final_entries_impl(input, false)?;
        // Commit cumulative_owed root (monotonic credits per (owner, asset)).
        let cum_entries = compute_cumulative_entries_impl(input, false)?;
        let balances_root = balances_merkle_root(&cum_entries);

        // Compute new filled_root via sparse updates using touched proofs.
        // Note: we intentionally avoid recomputing prev_filled_root from full lists to scale to large N.
        let filled_root = filled_root_sparse_update(input)?;
        let cancellations_root = cancellations_root_sparse_update(input)?;

        Ok(SettlementOutput {
            balances_root,
            prev_filled_root: input.prev_filled_root,
            filled_root,
            cancellations_root,
            match_count: input.matches.len() as u32,
        })
    }

    /// Compute orders root from list of order ids
    pub fn orders_root_from_list(order_ids: &[[u8; 32]]) -> [u8; 32] {
        let entries: Vec<([u8; 32], [u8; 32])> = order_ids
            .iter()
            .map(|oid| (*oid, crate::merkle::hash_order_leaf(*oid)))
            .collect();
        crate::merkle::merkle_root_from_unordered_kv(entries)
    }

    /// Compute filled root from list of orders and corresponding amounts
    pub fn filled_root_from_orders(orders: &[&Order], amounts: &[u128]) -> [u8; 32] {
        let entries: Vec<([u8; 32], [u8; 32])> = orders
            .iter()
            .enumerate()
            .map(|(i, o)| {
                let oid = order_struct_hash(o);
                (oid, crate::merkle::hash_filled_leaf(oid, amounts[i]))
            })
            .collect();
        crate::merkle::merkle_root_from_unordered_kv(entries)
    }

    /// Compute the sorted final (owner, asset, amount) entries after full validation.
    pub fn compute_final_entries(
        input: &SettlementInput,
    ) -> Result<Vec<(Address, Asset, u128)>, String> {
        compute_final_entries_impl(input, true)
    }

    /// Internal implementation with optional signature verification.
    fn compute_final_entries_impl(
        input: &SettlementInput,
        verify_sigs: bool,
    ) -> Result<Vec<(Address, Asset, u128)>, String> {
        // 1) Basic checks.
        for (i, o) in input.orders.iter().enumerate() {
            if o.price_d == 0 {
                return Err(format!("order {} has zero price_d", i));
            }
            if input.timestamp > o.expiry {
                return Err(format!("order {} expired", i));
            }
        }

        // 2) Verify signatures for all orders.
        if verify_sigs {
            for (i, o) in input.orders.iter().enumerate() {
                if !verify_order_sig(o, &input.domain) {
                    return Err(format!("invalid signature for order {}", i));
                }
            }
        }

        // 3) Track remaining amounts per order, subtracting prev_filled to prevent cross-batch overfill.
        let mut remaining: Vec<u128> = Vec::with_capacity(input.orders.len());
        for (i, o) in input.orders.iter().enumerate() {
            let prev = *input.prev_filled.get(i).unwrap_or(&0);
            if prev > o.amount {
                return Err("prev_filled exceeds order amount".to_string());
            }
            remaining.push(o.amount - prev);
        }

        // 4) Compute expected deltas from matches, validating compatibility + limits.
        let mut computed: BTreeMap<(Address, Asset), i128> = BTreeMap::new();

        for (j, m) in input.matches.iter().enumerate() {
            let bi = m.buy_idx as usize;
            let si = m.sell_idx as usize;
            if bi >= input.orders.len() || si >= input.orders.len() {
                return Err(format!("match {} references out-of-bounds order index", j));
            }
            let buy = &input.orders[bi];
            let sell = &input.orders[si];

            // Enforce sides.
            match (&buy.side, &sell.side) {
                (Side::Buy, Side::Sell) => {}
                _ => return Err(format!("match {} must pair Buy with Sell", j)),
            }

            // Asset pair must match.
            if buy.base != sell.base || buy.quote != sell.quote {
                return Err(format!("match {} asset mismatch", j));
            }

            // Fill amount and quote paid must be > 0
            if m.base_filled == 0 || m.quote_paid == 0 {
                return Err(format!("match {} has zero amounts", j));
            }

            // Do not exceed remaining.
            if m.base_filled > remaining[bi] || m.base_filled > remaining[si] {
                return Err(format!("match {} overfills an order", j));
            }

            // Price compatibility: buyer limit >= effective price, seller limit <= effective price.
            // effective_price = quote_paid / base_filled. Compare as fractions to avoid FP.
            let ef_q = m.quote_paid;
            let ef_b = m.base_filled;

            // buyer_limit >= eff => buy.price_n/buy.price_d >= ef_q/ef_b
            // => buy.price_n * ef_b >= ef_q * buy.price_d
            let lhs_buy = buy
                .price_n
                .checked_mul(ef_b)
                .ok_or_else(|| format!("price multiplication overflow (buy match {})", j))?;
            let rhs_buy = ef_q
                .checked_mul(buy.price_d)
                .ok_or_else(|| format!("price multiplication overflow (buy match {})", j))?;
            if lhs_buy < rhs_buy {
                return Err(format!("match {} violates buyer price limit", j));
            }

            // seller_limit <= eff => sell.price_n/sell.price_d <= ef_q/ef_b
            let lhs_sell = sell
                .price_n
                .checked_mul(ef_b)
                .ok_or_else(|| format!("price multiplication overflow (sell match {})", j))?;
            let rhs_sell = ef_q
                .checked_mul(sell.price_d)
                .ok_or_else(|| format!("price multiplication overflow (sell match {})", j))?;
            if lhs_sell > rhs_sell {
                return Err(format!("match {} violates seller price limit", j));
            }

            // Update remaining.
            remaining[bi] -= m.base_filled;
            remaining[si] -= m.base_filled;

            // Compute deltas.
            // Buyer: +base, -quote
            let bf_i128 = i128::try_from(m.base_filled)
                .map_err(|_| "base_filled exceeds i128 range".to_string())?;
            let qp_i128 = i128::try_from(m.quote_paid)
                .map_err(|_| "quote_paid exceeds i128 range".to_string())?;
            acc_delta(&mut computed, (buy.maker, buy.base), bf_i128);
            acc_delta(&mut computed, (buy.maker, buy.quote), -qp_i128);

            // Seller: -base, +quote
            acc_delta(&mut computed, (sell.maker, sell.base), -bf_i128);
            acc_delta(&mut computed, (sell.maker, sell.quote), qp_i128);
        }

        // 5) Validate proposed deltas exactly match computed deltas.
        let mut proposed: BTreeMap<(Address, Asset), i128> = BTreeMap::new();
        for d in &input.proposed_deltas {
            acc_delta(&mut proposed, (d.owner, d.asset), d.delta);
        }
        if proposed.len() != computed.len() {
            return Err("proposed deltas size mismatch".to_string());
        }
        for (k, v) in computed.iter() {
            let pv = proposed.get(k).ok_or_else(|| "missing proposed delta".to_string())?;
            if pv != v {
                return Err("proposed delta differs from computed".to_string());
            }
        }

        // 6) Apply deltas to initial balances and ensure non-negative.
        let mut balances: BTreeMap<(Address, Asset), i128> = BTreeMap::new();
        for b in &input.initial_balances {
            let amt_i128 = i128::try_from(b.amount).map_err(|_| "initial balance exceeds i128 range".to_string())?;
            acc_delta(&mut balances, (b.owner, b.asset), amt_i128);
        }
        for (k, d) in computed.iter() {
            acc_delta(&mut balances, *k, *d);
        }

        // Ensure all balances >= 0 and convert to final u128 for hashing.
        let mut final_entries: Vec<(Address, Asset, u128)> = Vec::with_capacity(balances.len());
        for (k, v) in balances.into_iter() {
            if v < 0 {
                return Err("negative final balance".to_string());
            }
            final_entries.push((k.0, k.1, u128::try_from(v).expect("final balance should fit in u128")));
        }

        // BTreeMap iteration already yields (owner, asset) in sorted order; no extra sort needed.
        Ok(final_entries)
    }

    /// Compute cumulative_owed entries: previous cumulative (from initial_balances.amount)
    /// plus positive deltas from this batch; negative deltas do not decrease owed.
    pub fn compute_cumulative_entries(
        input: &SettlementInput,
    ) -> Result<Vec<(Address, Asset, u128)>, String> {
        compute_cumulative_entries_impl(input, true)
    }

    /// Internal implementation with optional signature verification.
    fn compute_cumulative_entries_impl(
        input: &SettlementInput,
        verify_sigs: bool,
    ) -> Result<Vec<(Address, Asset, u128)>, String> {
        // Reuse the same validation structure to compute deltas and validate matches.
        for (i, o) in input.orders.iter().enumerate() {
            if o.price_d == 0 {
                return Err(format!("order {} has zero price_d", i));
            }
            if input.timestamp > o.expiry {
                return Err(format!("order {} expired", i));
            }
        }
        if verify_sigs {
            for (i, o) in input.orders.iter().enumerate() {
                if !verify_order_sig(o, &input.domain) {
                    return Err(format!("invalid signature for order {}", i));
                }
            }
        }
        let mut remaining: Vec<u128> = Vec::with_capacity(input.orders.len());
        for (i, o) in input.orders.iter().enumerate() {
            let prev = *input.prev_filled.get(i).unwrap_or(&0);
            if prev > o.amount {
                return Err("prev_filled exceeds order amount".to_string());
            }
            remaining.push(o.amount - prev);
        }
        let mut computed: BTreeMap<(Address, Asset), i128> = BTreeMap::new();
        for (j, m) in input.matches.iter().enumerate() {
            let bi = m.buy_idx as usize;
            let si = m.sell_idx as usize;
            if bi >= input.orders.len() || si >= input.orders.len() {
                return Err(format!("match {} references out-of-bounds order index", j));
            }
            let buy = &input.orders[bi];
            let sell = &input.orders[si];
            match (&buy.side, &sell.side) {
                (Side::Buy, Side::Sell) => {}
                _ => return Err(format!("match {} must pair Buy with Sell", j)),
            }
            if buy.base != sell.base || buy.quote != sell.quote {
                return Err(format!("match {} asset mismatch", j));
            }
            if m.base_filled == 0 || m.quote_paid == 0 {
                return Err(format!("match {} has zero amounts", j));
            }
            if m.base_filled > remaining[bi] || m.base_filled > remaining[si] {
                return Err(format!("match {} overfills an order", j));
            }
            let ef_q = m.quote_paid;
            let ef_b = m.base_filled;
            let lhs_buy = buy
                .price_n
                .checked_mul(ef_b)
                .ok_or_else(|| format!("price multiplication overflow (buy match {})", j))?;
            let rhs_buy = ef_q
                .checked_mul(buy.price_d)
                .ok_or_else(|| format!("price multiplication overflow (buy match {})", j))?;
            if lhs_buy < rhs_buy {
                return Err(format!("match {} violates buyer price limit", j));
            }
            let lhs_sell = sell
                .price_n
                .checked_mul(ef_b)
                .ok_or_else(|| format!("price multiplication overflow (sell match {})", j))?;
            let rhs_sell = ef_q
                .checked_mul(sell.price_d)
                .ok_or_else(|| format!("price multiplication overflow (sell match {})", j))?;
            if lhs_sell > rhs_sell {
                return Err(format!("match {} violates seller price limit", j));
            }
            remaining[bi] -= m.base_filled;
            remaining[si] -= m.base_filled;
            let bf_i128 = i128::try_from(m.base_filled)
                .map_err(|_| "base_filled exceeds i128 range".to_string())?;
            let qp_i128 = i128::try_from(m.quote_paid)
                .map_err(|_| "quote_paid exceeds i128 range".to_string())?;
            acc_delta(&mut computed, (buy.maker, buy.base), bf_i128);
            acc_delta(&mut computed, (buy.maker, buy.quote), -qp_i128);
            acc_delta(&mut computed, (sell.maker, sell.base), -bf_i128);
            acc_delta(&mut computed, (sell.maker, sell.quote), qp_i128);
        }
        // Validate proposed deltas
        let mut proposed: BTreeMap<(Address, Asset), i128> = BTreeMap::new();
        for d in &input.proposed_deltas {
            acc_delta(&mut proposed, (d.owner, d.asset), d.delta);
        }
        if proposed.len() != computed.len() {
            return Err("proposed deltas size mismatch".to_string());
        }
        for (k, v) in computed.iter() {
            let pv = proposed.get(k).ok_or_else(|| "missing proposed delta".to_string())?;
            if pv != v {
                return Err("proposed delta differs from computed".to_string());
            }
        }
        // Build cumulative owed: start from initial amounts and add only positive deltas.
        let mut cum: BTreeMap<(Address, Asset), u128> = BTreeMap::new();
        for b in &input.initial_balances {
            cum.insert((b.owner, b.asset), b.amount);
        }
        for (k, d) in computed.into_iter() {
            if d > 0 {
                let cur = cum.get(&k).copied().unwrap_or(0);
                let add = u128::try_from(d).map_err(|_| "cumulative delta exceeds u128 range".to_string())?;
                let newv = cur
                    .checked_add(add)
                    .ok_or_else(|| "cumulative owed overflow".to_string())?;
                cum.insert(k, newv);
            }
        }
        let mut out: Vec<(Address, Asset, u128)> = cum.into_iter().map(|(k, v)| (k.0, k.1, v)).collect();
        out.sort_by(|a, b| cmp_key(&(a.0, a.1), &(b.0, b.1)));
        Ok(out)
    }

    fn acc_delta(map: &mut BTreeMap<(Address, Asset), i128>, key: (Address, Asset), delta: i128) {
        *map.entry(key).or_insert(0) += delta;
    }

    fn cmp_key(a: &(Address, Asset), b: &(Address, Asset)) -> Ordering {
        match a.0.cmp(&b.0) {
            Ordering::Equal => a.1.cmp(&b.1),
            o => o,
        }
    }

    fn balances_merkle_root(entries: &[(Address, Asset, u128)]) -> [u8; 32] {
        // Leaf hash: keccak256(owner(20) || asset(32) || amount_be16)
        let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(entries.len());
        for (addr, asset, amt) in entries {
            let mut h = Keccak256::new();
            h.update(addr);
            h.update(asset);
            h.update(&amt.to_be_bytes()); // 16 bytes
            let out = h.finalize();
            let mut leaf = [0u8; 32];
            leaf.copy_from_slice(&out);
            leaves.push(leaf);
        }

        if leaves.is_empty() {
            let out = Keccak256::digest([]);
            let mut root = [0u8; 32];
            root.copy_from_slice(&out);
            return root;
        }

        let mut level = leaves;
        while level.len() > 1 {
            let mut next: Vec<[u8; 32]> = Vec::with_capacity((level.len() + 1) / 2);
            let mut i = 0;
            while i < level.len() {
                if i + 1 < level.len() {
                    let a = level[i];
                    let b = level[i + 1];
                    // Sorted pair hashing: keccak256(min(a,b) || max(a,b))
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
                    // Promote odd hash
                    next.push(level[i]);
                    i += 1;
                }
            }
            level = next;
        }
        level[0]
    }

    // Removed full-list cumulative root recomputation in favor of sparse updates.

    /// Compute new filled_root by applying sparse updates to prev_filled_root using the
    /// provided touched proofs. This scales with O(T log N) where T is the number of
    /// touched orders and N the total number of orders in the global tree.
    fn filled_root_sparse_update(input: &SettlementInput) -> Result<[u8; 32], String> {
        use crate::merkle::{fold_sorted_pair, hash_filled_leaf};
        use std::collections::BTreeMap;

        // Aggregate this-batch base fill per touched order index.
        let mut this_batch_fill: BTreeMap<usize, u128> = BTreeMap::new();
        for m in &input.matches {
            let bi = m.buy_idx as usize;
            let si = m.sell_idx as usize;
            if bi >= input.orders.len() || si >= input.orders.len() {
                return Err("match references out-of-bounds order index".to_string());
            }
            let e_b = this_batch_fill.entry(bi).or_insert(0);
            *e_b = e_b
                .checked_add(m.base_filled)
                .ok_or_else(|| "batch fill overflow".to_string())?;
            let e_s = this_batch_fill.entry(si).or_insert(0);
            *e_s = e_s
                .checked_add(m.base_filled)
                .ok_or_else(|| "batch fill overflow".to_string())?;
        }

        // Build a map from order index to its touched proof for quick lookup and verify basic bindings.
        let mut touched_by_index: BTreeMap<usize, &TouchedProof> = BTreeMap::new();
        for tp in &input.orders_touched {
            let idx = tp.order_index as usize;
            if touched_by_index.insert(idx, tp).is_some() {
                return Err("duplicate touched proof for order index".to_string());
            }
        }

        // Ghost order protection: every touched order must be matched in this batch.
        for tp in &input.orders_touched {
            let idx = tp.order_index as usize;
            if !this_batch_fill.contains_key(&idx) {
                return Err("touched order not matched in this batch".to_string());
            }
        }

        // Verify that every matched order has a touched proof and compute updated leaves.
        // Also precompute old path nodes for each proof for later merging.
        struct PathCache {
            old_nodes: Vec<[u8; 32]>, // level 0 = old leaf, last = root
            proof: Vec<[u8; 32]>,
            new_leaf: [u8; 32],
            order_id: [u8; 32],
        }
        let mut caches: BTreeMap<usize, PathCache> = BTreeMap::new();

        // Helper: compute orderId from an order
        fn order_id_of(order: &Order) -> [u8; 32] { order_struct_hash(order) }

        for (idx, order) in input.orders.iter().enumerate() {
            if let Some(fill) = this_batch_fill.get(&idx).copied() {
                let tp = touched_by_index.get(&idx).ok_or_else(|| "missing touched proof for matched order".to_string())?;
                // Verify order_id matches the order data.
                let oid_calc = order_id_of(order);
                if tp.order_id != oid_calc {
                    return Err("touched order_id mismatch".to_string());
                }
                // Verify ordersRoot inclusion
                let order_leaf = crate::merkle::hash_order_leaf(tp.order_id);
                if !crate::merkle::verify_merkle_proof_sorted_keccak(order_leaf, &tp.orders_proof, input.orders_root) {
                    return Err("ordersRoot inclusion proof failed".to_string());
                }
                // Verify prevFilledRoot inclusion for prev value
                let filled_leaf_prev = crate::merkle::hash_filled_leaf(tp.order_id, tp.prev_filled);
                if !crate::merkle::verify_merkle_proof_sorted_keccak(filled_leaf_prev, &tp.filled_proof, input.prev_filled_root) {
                    return Err("prevFilledRoot inclusion proof failed".to_string());
                }
                // cancellations_root value must be 0 (not canceled)
                let cancel_leaf = crate::merkle::hash_filled_leaf(tp.order_id, 0);
                if !crate::merkle::verify_merkle_proof_sorted_keccak(cancel_leaf, &tp.cancel_proof, input.cancellations_root) {
                    return Err("cancellationsRoot inclusion proof failed".to_string());
                }

                // Optional consistency: if a prev_filled list is provided for this index, ensure equality.
                if let Some(prev_list) = input.prev_filled.get(idx) {
                    if *prev_list != tp.prev_filled {
                        return Err("prev_filled mismatch between list and touched proof".to_string());
                    }
                }

                // Precompute old path nodes up to root for this proof.
                let mut old_nodes: Vec<[u8; 32]> = Vec::with_capacity(tp.filled_proof.len() + 1);
                let mut cur = filled_leaf_prev;
                old_nodes.push(cur);
                for sib in &tp.filled_proof {
                    cur = fold_sorted_pair(cur, *sib);
                    old_nodes.push(cur);
                }
                // Sanity: path reaches prev_filled_root
                if *old_nodes.last().expect("old_nodes should not be empty") != input.prev_filled_root {
                    return Err("filled proof does not lead to prevFilledRoot".to_string());
                }

                // Compute new leaf hash with added fill.
                let new_filled = tp
                    .prev_filled
                    .checked_add(fill)
                    .ok_or_else(|| "fill amount overflow".to_string())?;
                let new_leaf = hash_filled_leaf(tp.order_id, new_filled);

                caches.insert(idx, PathCache { old_nodes, proof: tp.filled_proof.clone(), new_leaf, order_id: tp.order_id });
            }
        }

        // Validate cache structure (old_nodes must be proof.len() + 1)
        for (_i, c) in caches.iter() {
            if c.old_nodes.len() != c.proof.len() + 1 {
                return Err("inconsistent path cache structure".to_string());
            }
        }

        // Deterministic path processing: sort caches by (order_id, index) for stability
        let mut sorted: Vec<(usize, PathCache)> = caches.into_iter().collect();
        sorted.sort_by(|a, b| match a.1.order_id.cmp(&b.1.order_id) {
            std::cmp::Ordering::Equal => a.0.cmp(&b.0),
            other => other,
        });

        // Level-by-level merge: level_maps[level][old_node] = new_node
        let mut level_maps: Vec<BTreeMap<[u8; 32], [u8; 32]>> = Vec::new();

        // Level 0: all leaves
        while level_maps.len() <= 0 { level_maps.push(BTreeMap::new()); }
        for (_idx, cache) in sorted.iter() {
            let old_leaf = cache.old_nodes[0];
            match level_maps[0].get(&old_leaf) {
                Some(existing) if existing != &cache.new_leaf => return Err("conflicting leaf updates".to_string()),
                _ => { level_maps[0].insert(old_leaf, cache.new_leaf); }
            }
        }

        // Determine max depth and enforce a reasonable bound
        let max_depth = sorted.iter().map(|(_, c)| c.proof.len()).max().unwrap_or(0);
        const MAX_TREE_DEPTH: usize = 50;
        if max_depth > MAX_TREE_DEPTH { return Err("tree depth exceeds maximum".to_string()); }

        // Build parents level-by-level
        for lvl in 0..max_depth {
            while level_maps.len() <= lvl { level_maps.push(BTreeMap::new()); }
            while level_maps.len() <= lvl + 1 { level_maps.push(BTreeMap::new()); }
            for (_idx, cache) in sorted.iter() {
                if lvl < cache.proof.len() {
                    let child_old = cache.old_nodes[lvl];
                    let child_new = level_maps[lvl]
                        .get(&child_old)
                        .copied()
                        .ok_or_else(|| "missing child node in level map".to_string())?;
                    let sib_old = cache.proof[lvl];
                    let sib_new = level_maps[lvl].get(&sib_old).copied().unwrap_or(sib_old);
                    let parent_new = fold_sorted_pair(child_new, sib_new);
                    let parent_old = cache.old_nodes[lvl + 1];
                    match level_maps[lvl + 1].get(&parent_old) {
                        Some(existing) if existing != &parent_new => return Err("conflicting parent updates".to_string()),
                        _ => { level_maps[lvl + 1].insert(parent_old, parent_new); }
                    }
                }
            }
        }

        // New root at top level (handle empty updates)
        let h = level_maps.len().saturating_sub(1);
        let final_root = match level_maps.get(h).and_then(|m| m.get(&input.prev_filled_root)).copied() {
            Some(root) => root,
            None => input.prev_filled_root, // No updates applied (no matches) => root unchanged
        };

        // Tree consistency validation: each updated path must recompute to final_root
        for (_idx, cache) in sorted.iter() {
            let mut cur = cache.new_leaf;
            for (i, sib_old) in cache.proof.iter().copied().enumerate() {
                let sib_new = level_maps[i].get(&sib_old).copied().unwrap_or(sib_old);
                cur = fold_sorted_pair(cur, sib_new);
            }
            if cur != final_root { return Err("path root mismatch after merge".to_string()); }
        }

        Ok(final_root)
    }

    // Removed unused helper that recomputed filled root from full lists.

    // Merkle helpers moved to crate::merkle (shared across lib/tests/scripts)

    fn cancellations_root_sparse_update(input: &SettlementInput) -> Result<[u8; 32], String> {
        use std::collections::BTreeMap;
        // Early exit
        if input.cancellations_updates.is_empty() { return Ok(input.cancellations_root); }

        // Forbid updates that touch matched orders in this batch
        let mut matched_ids = BTreeMap::new();
        for m in &input.matches {
            let bi = m.buy_idx as usize;
            let si = m.sell_idx as usize;
            if bi < input.orders.len() { matched_ids.insert(order_struct_hash(&input.orders[bi]), ()); }
            if si < input.orders.len() { matched_ids.insert(order_struct_hash(&input.orders[si]), ()); }
        }
        for u in &input.cancellations_updates {
            if matched_ids.contains_key(&u.order_id) {
                return Err("cancellation update for matched order in same batch".to_string());
            }
            if !(u.new_value == 0 || u.new_value == 1) { return Err("invalid cancellation value".to_string()); }
            if !(u.prev_value == 0 || u.prev_value == 1) { return Err("invalid previous cancellation value".to_string()); }
            // Monotonic: prevent un-cancel; allow 0->1 or 0->0 or 1->1, but forbid 1->0
            if u.prev_value == 1 && u.new_value == 0 { return Err("cannot uncancel order".to_string()); }
        }

        // Build caches analogous to filled_root_sparse_update
        struct PathCache { old_nodes: Vec<[u8; 32]>, proof: Vec<[u8; 32]>, new_leaf: [u8; 32], order_id: [u8; 32] }
        let mut caches: BTreeMap<[u8; 32], PathCache> = BTreeMap::new();
        for u in &input.cancellations_updates {
            // Verify prev leaf inclusion
            let prev_leaf = crate::merkle::hash_filled_leaf(u.order_id, u.prev_value);
            // Build old path and check root
            let mut old_nodes: Vec<[u8; 32]> = Vec::with_capacity(u.proof.len() + 1);
            let mut cur = prev_leaf;
            old_nodes.push(cur);
            for sib in &u.proof {
                cur = fold_sorted_pair(cur, *sib);
                old_nodes.push(cur);
            }
            if *old_nodes.last().expect("old_nodes should not be empty") != input.cancellations_root {
                return Err("cancellation proof does not lead to cancellationsRoot".to_string());
            }
            let new_leaf = crate::merkle::hash_filled_leaf(u.order_id, u.new_value);
            if caches.insert(u.order_id, PathCache { old_nodes, proof: u.proof.clone(), new_leaf, order_id: u.order_id }).is_some() {
                return Err("duplicate cancellation update for orderId".to_string());
            }
        }

        // Merge updates across levels
        let mut level_maps: Vec<BTreeMap<[u8; 32], [u8; 32]>> = Vec::new();
        let max_depth = caches.values().map(|c| c.proof.len()).max().unwrap_or(0);
        const MAX_TREE_DEPTH: usize = 50;
        if max_depth > MAX_TREE_DEPTH { return Err("tree depth exceeds maximum".to_string()); }

        // Seed level 0 replacements: old leaf -> new leaf
        level_maps.push(BTreeMap::new());
        for (_oid, c) in caches.iter() {
            level_maps[0].insert(c.old_nodes[0], c.new_leaf);
        }

        let mut caches_sorted: Vec<&PathCache> = caches.values().collect();
        caches_sorted.sort_by(|a, b| a.order_id.cmp(&b.order_id));

        for lvl in 0..max_depth {
            while level_maps.len() <= lvl + 1 { level_maps.push(BTreeMap::new()); }
            for c in &caches_sorted {
                if lvl < c.proof.len() {
                    let child_old = c.old_nodes[lvl];
                    let child_new = *level_maps[lvl].get(&child_old).ok_or_else(|| "missing child node in level map".to_string())?;
                    let sib_old = c.proof[lvl];
                    let sib_new = *level_maps[lvl].get(&sib_old).unwrap_or(&sib_old);
                    let parent_new = fold_sorted_pair(child_new, sib_new);
                    let parent_old = c.old_nodes[lvl + 1];
                    match level_maps[lvl + 1].get(&parent_old) {
                        Some(existing) if *existing != parent_new => return Err("conflicting parent updates in cancellations".to_string()),
                        _ => { level_maps[lvl + 1].insert(parent_old, parent_new); }
                    }
                }
            }
        }

        let h = level_maps.len().saturating_sub(1);
        let final_root = match level_maps.get(h).and_then(|m| m.get(&input.cancellations_root)).copied() {
            Some(root) => root,
            None => input.cancellations_root,
        };

        // Validate each updated path recomputes to final_root
        for c in &caches_sorted {
            let mut cur = c.new_leaf;
            for (i, sib_old) in c.proof.iter().copied().enumerate() {
                let sib_new = *level_maps[i].get(&sib_old).unwrap_or(&sib_old);
                cur = fold_sorted_pair(cur, sib_new);
            }
            if cur != final_root { return Err("cancellations path root mismatch after merge".to_string()); }
        }

        Ok(final_root)
    }

    pub fn eip712_domain_separator(domain: &Domain) -> [u8; 32] {
        // typehash = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)")
        let mut keccak = Keccak256::new();
        keccak.update(b"EIP712Domain(uint256 chainId,address verifyingContract)");
        let typehash = keccak.finalize();

        let mut e = Keccak256::new();
        e.update(&typehash);
        // chainId (uint256) = left-padded 32-bytes
        let mut buf = [0u8; 32];
        buf[24..].copy_from_slice(&domain.chain_id.to_be_bytes());
        e.update(&buf);
        // verifyingContract (address) left-padded to 32
        let mut abuf = [0u8; 32];
        abuf[12..].copy_from_slice(&domain.exchange);
        e.update(&abuf);
        let out = e.finalize();
        let mut sep = [0u8; 32];
        sep.copy_from_slice(&out);
        sep
    }

    pub fn order_struct_hash(order: &Order) -> [u8; 32] {
        // typehash = keccak256(
        //   "Order(address maker,bytes32 base,bytes32 quote,uint8 side,uint128 price_n,uint128 price_d,uint128 amount,uint64 nonce,uint64 expiry)"
        // )
        let mut keccak = Keccak256::new();
        keccak.update(b"Order(address maker,bytes32 base,bytes32 quote,uint8 side,uint128 price_n,uint128 price_d,uint128 amount,uint64 nonce,uint64 expiry)");
        let typehash = keccak.finalize();

        let mut e = Keccak256::new();
        e.update(&typehash);
        // maker address
        let mut maker_buf = [0u8; 32];
        maker_buf[12..].copy_from_slice(&order.maker);
        e.update(&maker_buf);
        // base bytes32
        e.update(&order.base);
        // quote bytes32
        e.update(&order.quote);
        // side as uint8 padded
        let mut side_buf = [0u8; 32];
        side_buf[31] = match order.side { Side::Buy => 0u8, Side::Sell => 1u8 };
        e.update(&side_buf);
        // price_n, price_d, amount as uint128 padded
        let mut u128buf = [0u8; 32];
        u128buf[16..].copy_from_slice(&order.price_n.to_be_bytes());
        e.update(&u128buf);
        u128buf[16..].copy_from_slice(&order.price_d.to_be_bytes());
        e.update(&u128buf);
        u128buf[16..].copy_from_slice(&order.amount.to_be_bytes());
        e.update(&u128buf);
        // nonce uint64 padded
        let mut u64buf = [0u8; 32];
        u64buf[24..].copy_from_slice(&order.nonce.to_be_bytes());
        e.update(&u64buf);
        // expiry uint64 padded
        u64buf[24..].copy_from_slice(&order.expiry.to_be_bytes());
        e.update(&u64buf);

        let out = e.finalize();
        let mut sh = [0u8; 32];
        sh.copy_from_slice(&out);
        sh
    }

    fn verify_order_sig(order: &Order, domain: &Domain) -> bool {
        use k256::ecdsa::RecoveryId;

        // Build EIP-712 digest: keccak256("\x19\x01" || domainSeparator || structHash)
        let domain_sep = eip712_domain_separator(domain);
        let struct_hash = order_struct_hash(order);
        let mut hasher = Keccak256::new();
        hasher.update(&[0x19, 0x01]);
        hasher.update(&domain_sep);
        hasher.update(&struct_hash);

        // Enforce canonical signature to prevent malleability: v in {27,28}, s <= n/2, r,s != 0
        // secp256k1 group order: FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        // half order:          7FFFFFFF FFFFFFFF FFFFFFFF 7FFFFFFF 5D576E73 57A4501D DFE92F46 681B20A0
        const N_OVER_2: [u8; 32] = [
            0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0x7F,0xFF,0xFF,0xFF,
            0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,
            0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0,
        ];
        if !(order.v == 27 || order.v == 28) { return false; }
        if order.s == [0u8; 32] || order.r == [0u8; 32] { return false; }
        if order.s > N_OVER_2 { return false; }

        // Build recoverable signature (r,s,v)
        let rec_id = match order.v { 27 => 0u8, 28 => 1u8, _ => unreachable!() };
        let sig = match Signature::from_bytes((&{
            let mut b = [0u8; 64];
            b[..32].copy_from_slice(&order.r);
            b[32..].copy_from_slice(&order.s);
            b
        }).into()) {
            Ok(s) => s,
            Err(_) => return false,
        };
        // Recover verifying key and derive maker address
        let rid = match RecoveryId::from_byte(rec_id) { Some(r) => r, None => return false };
        let vk = match VerifyingKey::recover_from_digest(hasher, &sig, rid) {
            Ok(vk) => vk,
            Err(_) => return false,
        };
        let pub_uncompressed = vk.to_encoded_point(false);
        let bytes = pub_uncompressed.as_bytes();
        let mut keccak = Keccak256::new();
        keccak.update(&bytes[1..]);
        let out = keccak.finalize();
        &out[12..] == &order.maker
    }

    /// Recoverable signing helper (host-side convenience): sign (r,s) and derive v by recovery.
    pub fn sign_order(
        order: &Order,
        domain: &Domain,
        sk: &k256::ecdsa::SigningKey,
    ) -> Result<(u8, [u8; 32], [u8; 32]), String> {
        use k256::ecdsa::{signature::DigestSigner, Signature, VerifyingKey};
        use k256::ecdsa::RecoveryId;

        // Build EIP-712 digest
        let domain_sep = eip712_domain_separator(domain);
        let struct_hash = order_struct_hash(order);
        let mut hasher_sign = Keccak256::new();
        hasher_sign.update(&[0x19, 0x01]);
        hasher_sign.update(&domain_sep);
        hasher_sign.update(&struct_hash);
        let sig: Signature = sk.sign_digest(hasher_sign);

        let bytes = sig.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);

        // Determine v by trying both recoveries
        let vk_expected: VerifyingKey = *sk.verifying_key();
        let v = {
            let mut hasher0 = Keccak256::new();
            hasher0.update(&[0x19, 0x01]);
            hasher0.update(&domain_sep);
            hasher0.update(&struct_hash);
            let rec0 = VerifyingKey::recover_from_digest(hasher0, &sig, RecoveryId::from_byte(0).expect("0 is valid recovery id"));

            let mut hasher1 = Keccak256::new();
            hasher1.update(&[0x19, 0x01]);
            hasher1.update(&domain_sep);
            hasher1.update(&struct_hash);
            let rec1 = VerifyingKey::recover_from_digest(hasher1, &sig, RecoveryId::from_byte(1).expect("1 is valid recovery id"));

            match (rec0.ok(), rec1.ok()) {
                (Some(vk), _) if vk == vk_expected => 27,
                (_, Some(vk)) if vk == vk_expected => 28,
                _ => return Err("signature recovery failed".to_string()),
            }
        };

        Ok((v, r, s))
    }

    /// Derive Ethereum-style address from a signing key (host convenience)
    pub fn addr_from_signer(sk: &k256::ecdsa::SigningKey) -> [u8; 20] {
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
}
