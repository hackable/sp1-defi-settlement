pub mod json {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub struct DomainJson { pub chain_id: String, pub exchange: String }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct OrderJson {
        pub maker: String,
        pub base: String,
        pub quote: String,
        pub side: String,
        pub price_n: String,
        pub price_d: String,
        pub amount: String,
        pub nonce: String,
        pub expiry: String,
        pub v: u8,
        pub r: String,
        pub s: String,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct MatchJson { pub buy_idx: u32, pub sell_idx: u32, pub base_filled: String, pub quote_paid: String }

    #[derive(Serialize, Deserialize)]
    pub struct BalanceJson { pub owner: String, pub asset: String, pub amount: String }

    #[derive(Serialize, Deserialize)]
    pub struct DeltaJson { pub owner: String, pub asset: String, pub delta: String }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct InputJson {
        pub domain: DomainJson,
        pub orders: Vec<OrderJson>,
        pub matches: Vec<MatchJson>,
        pub initial_balances: Vec<BalanceJson>,
        pub proposed_deltas: Vec<DeltaJson>,
        pub timestamp: String,
        // Optional cancellations updates to be applied (sparse)
        #[serde(default)]
        pub cancellations_updates: Option<Vec<CancellationUpdateJson>>,
        // Optional touched proofs list (if provided externally)
        #[serde(default)]
        pub orders_touched: Option<Vec<TouchedProofJson>>,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct CancellationUpdateJson {
        #[serde(rename = "orderId")] pub order_id: String,
        pub prev_value: String,
        pub new_value: String,
        pub proof: Vec<String>,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TouchedProofJson {
        pub order_index: u32,
        #[serde(rename = "orderId")] pub order_id: String,
        pub prev_filled: String,
        pub filled_proof: Vec<String>,
        pub orders_proof: Vec<String>,
        pub cancel_proof: Vec<String>,
    }
}
