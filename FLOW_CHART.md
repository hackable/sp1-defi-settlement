# DeFi Settlement System - Complete Flow Chart

## Overview

This document describes the complete end-to-end flow of the SP1 DeFi Settlement system, from order creation to withdrawal. The system uses zero-knowledge proofs to enable billion-order scale settlement with sparse Merkle tree updates.

---

## 1. ORDER CREATION & SIGNING FLOW

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   User/Trader   │    │  Exchange/Maker  │    │  Domain Setup   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │ 1. Create Order       │                       │
         │────────────────────►  │                       │
         │                       │ 2. Set Domain         │
         │                       │────────────────────►  │
         │                       │                       │
         │                       │ Domain {              │
         │                       │   chain_id: 1,        │
         │                       │   exchange: 0x1111... │
         │                       │ }                     │
         │                       │                       │
         │                       │ 3. Build Order Struct │
         │                       │◄───────────────────── │
         │                       │                       │
         │                       │ Order {               │
         │                       │   maker: 0xABC...,    │
         │                       │   base: 0xAAA...,     │
         │                       │   quote: 0xBBB...,    │
         │                       │   side: Buy/Sell,     │
         │                       │   price_n: 3,         │
         │                       │   price_d: 1,         │
         │                       │   amount: 10,         │
         │                       │   nonce: 100,         │
         │                       │   expiry: MAX,        │
         │                       │   v: 0, r: [], s: []  │
         │                       │ }                     │
         │                       │                       │
```

### Step 1A: EIP-712 Domain Separator Creation

```
┌─────────────────────────────────────────────────────────────────┐
│                    eip712_domain_separator()                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  typehash = keccak256("EIP712Domain(uint256 chainId,address     │
│                       verifyingContract)")                      │
│                                                                 │
│  domainSeparator = keccak256(                                   │
│    typehash ||                                                  │
│    chainId (32 bytes) ||                                        │
│    exchange (32 bytes)                                          │
│  )                                                              │
│                                                                 │
│  Result: 0xf0dcfe86ad4a409690a57dbaae9b1e14c5ea1750...          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Step 1B: Order Struct Hash Creation

```
┌─────────────────────────────────────────────────────────────────┐
│                      order_struct_hash()                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  orderTypeHash = keccak256("Order(address maker,bytes32 base,   │
│                           bytes32 quote,uint8 side,uint256      │
│                           price_n,uint256 price_d,uint256       │
│                           amount,uint256 nonce,uint256 expiry)")│
│                                                                 │
│  structHash = keccak256(                                        │
│    orderTypeHash ||                                             │
│    maker ||                                                     │
│    base ||                                                      │
│    quote ||                                                     │
│    side ||                                                      │
│    price_n ||                                                   │
│    price_d ||                                                   │
│    amount ||                                                    │
│    nonce ||                                                     │
│    expiry                                                       │
│  )                                                              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Step 1C: EIP-712 Signature Creation

```
┌─────────────────────────────────────────────────────────────────┐
│                        sign_order()                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  digest = keccak256(                                            │
│    0x1901 ||              ← EIP-712 magic prefix                │
│    domainSeparator ||      ← Binds to chain + exchange          │
│    structHash              ← Order data hash                    │
│  )                                                              │
│                                                                 │
│  signature = ECDSA_sign(private_key, digest)                    │
│                                                                 │
│  Extract (r, s) from signature                                  │
│  Determine v by recovery (27 or 28)                             │
│                                                                 │
│  Return: (v, r, s)                                              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. ORDER MATCHING & SETTLEMENT INPUT PREPARATION

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Order Book     │    │  Matching Engine │    │ Settlement Prep │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │ Multiple signed       │                       │
         │ orders collected      │                       │
         │────────────────────►  │                       │
         │                       │                       │
         │                       │ 1. Find matches       │
         │                       │    (buy/sell pairs)   │
         │                       │                       │
         │                       │ 2. Calculate fills    │
         │                       │    & price validation │
         │                       │                       │
         │                       │ 3. Build MatchFill    │
         │                       │    objects            │
         │                       │────────────────────►  │
         │                       │                       │
         │                       │                       │ 4. Compute balance
         │                       │                       │    deltas
         │                       │                       │
         │                       │                       │ 5. Build touched
         │                       │                       │    proofs (sparse)
         │                       │                       │
         │                       │                       │ 6. Create
         │                       │                       │    SettlementInput
```

### Settlement Input Structure

```json
{
  "domain": {
    "chain_id": "1",
    "exchange": "0x1111111111111111111111111111111111111111"
  },
  "orders": [
    {
      "maker": "0x1a642f0e3c3af545e7acbd38b07251b3990914f1",
      "base": "0xaaaa...",
      "quote": "0xbbbb...",
      "side": "Buy",
      "priceN": "3",
      "priceD": "1",
      "amount": "10",
      "nonce": "100",
      "expiry": "18446744073709551615",
      "v": 28,
      "r": "0xb66a8e350f2f3c1185824422a6caa3e1538c16fcb28584b875a6e21220595ca3",
      "s": "0x12348ba46d6821d8480415556c786b5a672219f8435a5f4a2e6c8580e981a860"
    }
  ],
  "matches": [
    {
      "buyIdx": 0,
      "sellIdx": 1,
      "baseFilled": "5",
      "quotePaid": "10"
    }
  ],
  "initialBalances": [...],
  "proposedDeltas": [...],
  "ordersTouched": [...]
}
```

---

## 3. SP1 ZERO-KNOWLEDGE PROOF GENERATION

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Settlement Input│    │   SP1 zkVM       │    │  Proof Output   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │ JSON input            │                       │
         │────────────────────►  │                       │
         │                       │                       │
         │                       │ GUEST PROGRAM:        │
         │                       │                       │
         │                       │ 1. Parse input        │
         │                       │                       │
         │                       │ 2. Verify signatures  │
         │                       │    (EIP-712 + ECDSA)  │
         │                       │                       │
         │                       │ 3. Validate matches   │
         │                       │    & price rules      │
         │                       │                       │
         │                       │ 4. Check balance      │
         │                       │    arithmetic         │
         │                       │                       │
         │                       │ 5. Update Merkle      │
         │                       │    roots (sparse)     │
         │                       │                       │
         │                       │ 6. Compute public     │
         │                       │    values             │
         │                       │────────────────────►  │
         │                       │                       │
         │                       │                       │ PublicValues:
         │                       │                       │ - balancesRoot
         │                       │                       │ - prevFilledRoot
         │                       │                       │ - filledRoot
         │                       │                       │ - cancellationsRoot
         │                       │                       │ - domainSeparator
         │                       │                       │ - matchCount
```

### SP1 Guest Program Flow (`program/src/main.rs`)

```rust
pub fn main() {
    // 1. Read settlement input from host
    let input = sp1_zkvm::io::read::<SettlementInput>();

    // 2. Verify settlement (includes all validations)
    let out = verify_settlement(&input).expect("settlement verification failed");

    // 3. Compute domain separator
    let domain_sep = eip712_domain_separator(&input.domain);

    // 4. Create public values
    let pv = SettlementPublicValues {
        balancesRoot: out.balances_root.into(),
        prevFilledRoot: input.prev_filled_root.into(),
        filledRoot: out.filled_root.into(),
        cancellationsRoot: out.cancellations_root.into(),
        domainSeparator: domain_sep.into(),
        matchCount: out.match_count,
    };

    // 5. Commit public values to proof
    let bytes = SettlementPublicValues::abi_encode(&pv);
    sp1_zkvm::io::commit_slice(&bytes);
}
```

### Key Verification Steps in `verify_settlement()`

```
┌─────────────────────────────────────────────────────────────────┐
│                     verify_settlement()                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  For each order:                                                │
│    ✓ Signature verification (ECDSA + EIP-712)                   │
│    ✓ Canonical signature checks (low-s, v ∈ {27,28})            │
│    ✓ Maker address recovery                                     │
│                                                                 │
│  For each match:                                                │
│    ✓ Price validation (buy_price ≥ sell_price)                  │
│    ✓ Fill amount validation                                     │
│    ✓ Overflow protection                                        │
│                                                                 │
│  Balance verification:                                          │
│    ✓ Initial + deltas = final balances                          │
│    ✓ No negative balances                                       │
│    ✓ Conservation of assets                                     │
│                                                                 │
│  Sparse Merkle updates:                                         │
│    ✓ Update only touched orders (O(T log N))                    │
│    ✓ Verify inclusion proofs                                    │
│    ✓ Compute new roots                                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. ON-CHAIN VERIFICATION & ROOT UPDATES

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  SP1 Proof      │    │  Ledger Contract │    │  Updated State  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │ updateRoot(proof,     │                       │
         │           publicVals) │                       │
         │────────────────────►  │                       │
         │                       │                       │
         │                       │ 1. Verify SP1 proof   │
         │                       │    with verifier      │
         │                       │                       │
         │                       │ 2. Decode publicVals  │
         │                       │    (7 fields)         │
         │                       │                       │
         │                       │ 3. Validate domain    │
         │                       │    separator          │
         │                       │                       │
         │                       │ 4. Check prevFilled   │
         │                       │    root matches       │
         │                       │                       │
         │                       │ 5. Validate cancel    │
         │                       │    root matches       │
         │                       │                       │
         │                       │ 6. Update state       │
         │                       │    atomically         │
         │                       │────────────────────►  │
         │                       │                       │
         │                       │                       │ State Updated:
         │                       │                       │ - balancesRoot ✓
         │                       │                       │ - filledRoot ✓
         │                       │                       │ - Event emitted
```

### Ledger Contract Validation (`contracts/Ledger.sol`)

```solidity
function updateRoot(bytes calldata proof, bytes calldata publicValues) external {
    // 1. Verify SP1 proof
    require(verifier.verify(proof, publicValues), "invalid proof");

    // 2. Decode public values (7 fields now)
    (bytes32 newBalancesRoot, bytes32 prevFilledRoot, bytes32 newFilledRoot,
     bytes32 prevCancellationsRoot, bytes32 newCancellationsRoot,
     bytes32 domainSeparator, uint32 matchCount) =
        abi.decode(publicValues, (bytes32, bytes32, bytes32, bytes32, bytes32, bytes32, uint32));

    // 3. Validate domain separator (CRITICAL SECURITY CHECK)
    bytes32 expectedDomainSeparator = keccak256(abi.encode(
        keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"),
        block.chainid,
        address(this)
    ));
    require(domainSeparator == expectedDomainSeparator, "invalid domain separator");

    // 4. Validate state transitions
    require(prevFilledRoot == filledRoot, "filled root mismatch");
    require(prevCancellationsRoot == cancellationsRoot, "cancellations root mismatch");

    // 5. Update state atomically
    bytes32 oldBalancesRoot = balancesRoot;
    balancesRoot = newBalancesRoot;
    filledRoot = newFilledRoot;

    cancellationsRoot = newCancellationsRoot;

    emit RootUpdated(oldBalancesRoot, newBalancesRoot, prevFilledRoot,
                     newFilledRoot, prevCancellationsRoot, newCancellationsRoot, matchCount);
}
```

---

## 5. USER WITHDRAWAL FLOW

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│     User        │    │  Merkle Proof    │    │ Ledger Contract │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │ 1. Query balance      │                       │
         │ from leaves.json      │                       │
         │────────────────────►  │                       │
         │                       │                       │
         │                       │ 2. Generate proof     │
         │                       │ for (owner, asset)    │
         │                       │                       │
         │ 3. Get proof data     │                       │
         │◄───────────────────── │                       │
         │                       │                       │
         │ 4. withdraw(owner,    │                       │
         │     asset, cumOwed,   │                       │
         │     amount, proof[])  │                       │
         │─────────────────────────────────────────────► │
         │                       │                       │
         │                       │                       │ 5. Verify Merkle
         │                       │                       │    proof against
         │                       │                       │    balancesRoot
         │                       │                       │
         │                       │                       │ 6. Check spending
         │                       │                       │    limits
         │                       │                       │
         │                       │                       │ 7. Transfer tokens
         │                       │                       │    to user
         │ ✓ Tokens received     │                       │
         │◄──────────────────────────────────────────────│
```

### Withdrawal Validation

```solidity
function withdraw(address owner, bytes32 asset, uint128 cumulativeOwed,
                 uint256 amountToWithdraw, bytes32[] calldata proof) external {
    // 1. Authorization check
    require(msg.sender == owner, "only owner");

    // 2. Verify Merkle proof
    bytes32 leaf = BalancesLeaf.leafHash(owner, asset, cumulativeOwed);
    require(MerkleProofSorted.verify(proof, balancesRoot, leaf), "bad proof");

    // 3. Check spending limits (cumulative owed model)
    uint256 already = spent[owner][asset];
    require(already + amountToWithdraw <= cumulativeOwed, "exceeds cumulative");

    // 4. Update spent tracking
    spent[owner][asset] = already + amountToWithdraw;

    // 5. Transfer tokens
    address token = address(uint160(uint256(asset)));
    require(IERC20(token).transfer(owner, amountToWithdraw), "transfer failed");

    emit Withdrawn(balancesRoot, owner, asset, amountToWithdraw);
}
```

---

## 6. COMPLETE END-TO-END FLOW

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│   Order     │   │  Settlement │   │     SP1     │   │  On-Chain   │   │ Withdrawal  │
│  Creation   │──▶│  Matching   │──▶│    Proof    │──▶│   Update    │──▶│  Process    │
└─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
       │                 │                 │                 │                 │
   • EIP-712         • Find matches    • Verify sigs    • Verify proof   • Generate
     signatures      • Calculate       • Check rules    • Validate        Merkle proof
   • Domain            fills          • Update trees     domain sep      • Verify against
     binding         • Build proofs   • Commit public  • Check state       balancesRoot
   • Order struct    • Sparse           values           transitions    • Transfer tokens
     hashing           updates                         • Update roots
```

### Security Properties Maintained Throughout:

1. **Domain Binding**: Every signature is bound to specific chain + exchange
2. **Cross-Batch Protection**: prevFilledRoot prevents double-spending across batches
3. **Cancellation Safety**: cancellationsRoot ensures canceled orders can't be filled
4. **Sparse Updates**: Only touched orders updated, enabling billion-order scale
5. **Cumulative Owed Model**: Withdrawal-friendly accounting with spending limits
6. **Canonical Signatures**: Prevents signature malleability attacks
7. **Overflow Protection**: All arithmetic uses checked operations
8. **Deterministic Processing**: Sorted order prevents non-deterministic results

---

## 7. PERFORMANCE CHARACTERISTICS

### Complexity Analysis:
- **Order Book Size**: N orders total
- **Touched Orders**: T orders per batch (T << N)
- **Tree Updates**: O(T log N) instead of O(N)
- **Proof Size**: O(log N) per touched order
- **Verification**: O(T log N) on-chain

### Scale Targets:
- **1 billion orders** in order book
- **~1000 touched orders** per batch
- **Sub-second proof generation** with SP1 precompiles
- **Constant gas cost** regardless of order book size

This enables DEX-scale settlement with cryptographic guarantees and minimal on-chain footprint.
