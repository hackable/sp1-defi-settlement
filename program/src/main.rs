//! A zkVM program that verifies matching signed orders and settlement deltas update balances.

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use defi_lib::defi::{verify_settlement, SettlementInput};
use defi_lib::SettlementPublicValues;

pub fn main() {
    // Read settlement input from host.
    let input = sp1_zkvm::io::read::<SettlementInput>();

    // Verify and compute public result (EIP-712 signature checks inside).
    let out = verify_settlement(&input).expect("settlement verification failed");

    // Encode and commit public values to the proof.
    let pv = SettlementPublicValues {
        balancesRoot: alloy_sol_types::private::FixedBytes(out.balances_root),
        prevFilledRoot: alloy_sol_types::private::FixedBytes(out.prev_filled_root),
        filledRoot: alloy_sol_types::private::FixedBytes(out.filled_root),
        cancellationsRoot: alloy_sol_types::private::FixedBytes(out.cancellations_root),
        matchCount: out.match_count,
    };
    let bytes = SettlementPublicValues::abi_encode(&pv);
    sp1_zkvm::io::commit_slice(&bytes);
}
