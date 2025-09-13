use alloy_sol_types::sol;
use k256::ecdsa::signature::DigestVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

sol! {
    /// Public values for the DeFi settlement program.
    struct SettlementPublicValues {
        bytes32 balancesRoot;
        bytes32 prevFilledRoot;
        bytes32 filledRoot;
        uint32 matchCount;
    }
}


/// DeFi settlement verification module.
pub mod defi {
    use super::*;
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
        /// Uncompressed secp256k1 public key coordinates.
        pub pubkey_x: [u8; 32],
        pub pubkey_y: [u8; 32],
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
        // Optimized inputs: orders root and per-order proofs for touched orders.
        pub orders_root: [u8; 32],
        pub touched: Vec<TouchedProof>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct TouchedProof {
        pub order_index: u32,
        pub order_id: [u8; 32],
        pub prev_filled: u128,
        pub filled_proof: Vec<[u8; 32]>,
        pub orders_proof: Vec<[u8; 32]>,
    }

    #[derive(Clone, Debug)]
    pub struct SettlementOutput {
        pub balances_root: [u8; 32],
        pub prev_filled_root: [u8; 32],
        pub filled_root: [u8; 32],
        pub match_count: u32,
    }

    pub fn verify_settlement(input: &SettlementInput) -> Result<SettlementOutput, String> {
        // Verify per-order proofs for all touched orders and ensure coverage of matched indices.
        // Build map: index -> proof
        let mut touched_map = BTreeMap::new();
        for tp in &input.touched {
            if (tp.order_index as usize) >= input.orders.len() {
                return Err("touched order_index out of bounds".to_string());
            }
            // Verify ordersRoot inclusion
            let ord = &input.orders[tp.order_index as usize];
            let oid_calc = order_struct_hash(ord);
            if oid_calc != tp.order_id {
                return Err("touched order_id mismatch".to_string());
            }
            let order_leaf = hash_order_leaf(tp.order_id);
            if !verify_merkle_proof_sorted_keccak(order_leaf, &tp.orders_proof, input.orders_root) {
                return Err("ordersRoot inclusion proof failed".to_string());
            }
            // Verify prevFilledRoot inclusion for prev value
            // Prefer provided prev_filled in touched; must match input.prev_filled list for consistency.
            let prev_list = *input.prev_filled.get(tp.order_index as usize).unwrap_or(&0);
            if prev_list != tp.prev_filled {
                return Err("prev_filled mismatch between list and touched proof".to_string());
            }
            let filled_leaf_prev = hash_filled_leaf(tp.order_id, tp.prev_filled);
            if !verify_merkle_proof_sorted_keccak(filled_leaf_prev, &tp.filled_proof, input.prev_filled_root) {
                return Err("prevFilledRoot inclusion proof failed".to_string());
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

        // Perform full validation using snapshot balances logic (non-negativity, limits, deltas).
        let _final_entries = compute_final_entries(input)?;
        // Commit cumulative_owed root (monotonic credits per (owner, asset)).
        let cum_entries = compute_cumulative_entries(input)?;
        let balances_root = balances_merkle_root(&cum_entries);

        // Check prev_filled_root consistency and compute cumulative filled root.
        let prev_root_calc = filled_merkle_root_from_list(&input.orders, &input.prev_filled);
        if prev_root_calc != input.prev_filled_root {
            return Err("prev_filled_root does not match provided prev_filled list".to_string());
        }
        let filled_root = cumulative_filled_merkle_root(input)?;

        Ok(SettlementOutput { balances_root, prev_filled_root: input.prev_filled_root, filled_root, match_count: input.matches.len() as u32 })
    }

    /// Compute the sorted final (owner, asset, amount) entries after full validation.
    pub fn compute_final_entries(
        input: &SettlementInput,
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
        for (i, o) in input.orders.iter().enumerate() {
            if !verify_order_sig(o, &input.domain) {
                return Err(format!("invalid signature for order {}", i));
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
            if buy.price_n.saturating_mul(ef_b) < ef_q.saturating_mul(buy.price_d) {
                return Err(format!("match {} violates buyer price limit", j));
            }

            // seller_limit <= eff => sell.price_n/sell.price_d <= ef_q/ef_b
            if sell.price_n.saturating_mul(ef_b) > ef_q.saturating_mul(sell.price_d) {
                return Err(format!("match {} violates seller price limit", j));
            }

            // Update remaining.
            remaining[bi] -= m.base_filled;
            remaining[si] -= m.base_filled;

            // Compute deltas.
            // Buyer: +base, -quote
            acc_delta(
                &mut computed,
                (buy.maker, buy.base),
                i128::try_from(m.base_filled).unwrap(),
            );
            acc_delta(
                &mut computed,
                (buy.maker, buy.quote),
                -i128::try_from(m.quote_paid).unwrap(),
            );

            // Seller: -base, +quote
            acc_delta(
                &mut computed,
                (sell.maker, sell.base),
                -i128::try_from(m.base_filled).unwrap(),
            );
            acc_delta(
                &mut computed,
                (sell.maker, sell.quote),
                i128::try_from(m.quote_paid).unwrap(),
            );
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
            acc_delta(&mut balances, (b.owner, b.asset), i128::try_from(b.amount).unwrap());
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
            final_entries.push((k.0, k.1, u128::try_from(v).unwrap()));
        }

        // BTreeMap iteration already yields (owner, asset) in sorted order; no extra sort needed.
        Ok(final_entries)
    }

    /// Compute cumulative_owed entries: previous cumulative (from initial_balances.amount)
    /// plus positive deltas from this batch; negative deltas do not decrease owed.
    pub fn compute_cumulative_entries(
        input: &SettlementInput,
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
        for (i, o) in input.orders.iter().enumerate() {
            if !verify_order_sig(o, &input.domain) {
                return Err(format!("invalid signature for order {}", i));
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
            if buy.price_n.saturating_mul(ef_b) < ef_q.saturating_mul(buy.price_d) {
                return Err(format!("match {} violates buyer price limit", j));
            }
            if sell.price_n.saturating_mul(ef_b) > ef_q.saturating_mul(sell.price_d) {
                return Err(format!("match {} violates seller price limit", j));
            }
            remaining[bi] -= m.base_filled;
            remaining[si] -= m.base_filled;
            acc_delta(&mut computed, (buy.maker, buy.base), i128::try_from(m.base_filled).unwrap());
            acc_delta(&mut computed, (buy.maker, buy.quote), -i128::try_from(m.quote_paid).unwrap());
            acc_delta(&mut computed, (sell.maker, sell.base), -i128::try_from(m.base_filled).unwrap());
            acc_delta(&mut computed, (sell.maker, sell.quote), i128::try_from(m.quote_paid).unwrap());
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
                let add = u128::try_from(d).unwrap();
                let newv = cur.saturating_add(add);
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

    // Build Merkle root over (orderId, cumulativeFilled) where cumulativeFilled = prev_filled[i] + this_batch_fill[i].
    fn cumulative_filled_merkle_root(input: &SettlementInput) -> Result<[u8; 32], String> {
        if input.prev_filled.len() != input.orders.len() {
            return Err("prev_filled length must match orders".to_string());
        }
        let mut this_batch_fill: Vec<u128> = vec![0u128; input.orders.len()];
        for m in &input.matches {
            let bi = m.buy_idx as usize;
            let si = m.sell_idx as usize;
            if bi >= input.orders.len() || si >= input.orders.len() {
                return Err("match references out-of-bounds order index".to_string());
            }
            this_batch_fill[bi] = this_batch_fill[bi].saturating_add(m.base_filled);
            this_batch_fill[si] = this_batch_fill[si].saturating_add(m.base_filled);
        }

        // Build cumulative list
        let cum: Vec<u128> = input
            .prev_filled
            .iter()
            .copied()
            .enumerate()
            .map(|(i, prev)| prev.saturating_add(this_batch_fill[i]))
            .collect();
        Ok(filled_merkle_root_from_list(&input.orders, &cum))
    }

    fn filled_merkle_root_from_list(orders: &[Order], amounts: &[u128]) -> [u8; 32] {
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

    // --- Merkle helpers (sorted-pair Keccak) ---
    fn keccak(bytes: &[u8]) -> [u8; 32] {
        let mut h = Keccak256::new();
        h.update(bytes);
        let out = h.finalize();
        let mut a = [0u8; 32];
        a.copy_from_slice(&out);
        a
    }

    fn hash_order_leaf(order_id: [u8; 32]) -> [u8; 32] { keccak(&order_id) }

    fn hash_filled_leaf(order_id: [u8; 32], cumulative_filled: u128) -> [u8; 32] {
        let mut buf = [0u8; 48];
        buf[..32].copy_from_slice(&order_id);
        buf[32..].copy_from_slice(&cumulative_filled.to_be_bytes());
        keccak(&buf)
    }

    fn fold_sorted_pair(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&lo);
        buf[32..].copy_from_slice(&hi);
        keccak(&buf)
    }

    fn verify_merkle_proof_sorted_keccak(mut leaf: [u8; 32], proof: &[[u8; 32]], root: [u8; 32]) -> bool {
        for sib in proof {
            leaf = fold_sorted_pair(leaf, *sib);
        }
        leaf == root
    }

    fn eip712_domain_separator(domain: &Domain) -> [u8; 32] {
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

    fn order_struct_hash(order: &Order) -> [u8; 32] {
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
        // Build verifying key from provided uncompressed pubkey (0x04 || x || y)
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(&order.pubkey_x);
        sec1[33..].copy_from_slice(&order.pubkey_y);
        let vk = match VerifyingKey::from_sec1_bytes(&sec1) {
            Ok(vk) => vk,
            Err(_) => return false,
        };

        // Ensure provided maker address matches pubkey-derived address
        let mut keccak = Keccak256::new();
        // hash uncompressed pubkey without the 0x04 prefix
        let mut pk_bytes = [0u8; 64];
        pk_bytes[..32].copy_from_slice(&order.pubkey_x);
        pk_bytes[32..].copy_from_slice(&order.pubkey_y);
        keccak.update(&pk_bytes);
        let out = keccak.finalize();
        if &out[12..] != &order.maker {
            return false;
        }

        // Build EIP-712 digest: keccak256("\x19\x01" || domainSeparator || structHash)
        let domain_sep = eip712_domain_separator(domain);
        let struct_hash = order_struct_hash(order);
        let mut hasher = Keccak256::new();
        hasher.update(&[0x19, 0x01]);
        hasher.update(&domain_sep);
        hasher.update(&struct_hash);

        // Build signature
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&order.r);
        sig_bytes[32..].copy_from_slice(&order.s);
        let sig = match Signature::from_bytes((&sig_bytes).into()) {
            Ok(s) => s,
            Err(_) => return false,
        };

        vk.verify_digest(hasher, &sig).is_ok()
    }
}
