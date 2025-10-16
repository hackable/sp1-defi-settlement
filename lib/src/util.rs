use crate::defi::Side;

pub fn parse_hex<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let ss = s
        .strip_prefix("0x")
        .ok_or_else(|| "missing 0x prefix".to_string())?;
    if ss.len() != N * 2 {
        return Err(format!("expected {} hex chars, got {}", N * 2, ss.len()));
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(ss, &mut out).map_err(|_| "invalid hex".to_string())?;
    Ok(out)
}

pub fn to_u128(s: &str) -> Result<u128, String> {
    s.parse().map_err(|_| "invalid u128".to_string())
}
pub fn to_u64(s: &str) -> Result<u64, String> {
    s.parse().map_err(|_| "invalid u64".to_string())
}
pub fn to_i128(s: &str) -> Result<i128, String> {
    s.parse().map_err(|_| "invalid i128".to_string())
}

pub fn to_side(s: &str) -> Result<Side, String> {
    match s {
        "Buy" | "buy" => Ok(Side::Buy),
        "Sell" | "sell" => Ok(Side::Sell),
        _ => Err("invalid side".to_string()),
    }
}
