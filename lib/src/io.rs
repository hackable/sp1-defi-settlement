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
    }
}

