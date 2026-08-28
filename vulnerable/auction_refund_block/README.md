# `vulnerable/auction_refund_block`

## Vulnerability: Single-Slot Pull-Payment Refund in English Auction

**Severity:** High

## Description

The auction escrows a bidder's tokens on every `bid()` call and, following
the pull-payment pattern, expects an outbid bidder to reclaim their tokens
later via `withdraw()`. However, the contract records the outstanding
refund in a single shared `PendingReturnBidder` / `PendingReturnAmount`
slot instead of a per-bidder mapping. Each new outbid overwrites that slot
with the *previous* highest bidder's refund, discarding whatever entry was
already there — even if it was never claimed. This mirrors a well-known
historical bug in the original "SimpleAuction" Solidity tutorial contract.

## Exploit Scenario

1. Bidder A calls `bid(A, 100)` and becomes the highest bidder.
2. Bidder B calls `bid(B, 200)`, outbidding A. The pending-return slot now
   holds `(A, 100)`, unclaimed.
3. Before A calls `withdraw()`, bidder C calls `bid(C, 300)`, outbidding B.
   The pending-return slot is overwritten to `(B, 200)`.
4. A calls `withdraw()` and gets `panic!("nothing to withdraw")` — the slot
   no longer references A. A's 100 escrowed tokens remain locked inside the
   contract permanently; no function, including the admin-only
   `end_auction()`, can ever return them.

## Vulnerable Code

```rust
// see src/lib.rs
let prev_bidder: Option<Address> = env.storage().persistent().get(&DataKey::HighestBidder);
if let Some(prev_bidder) = prev_bidder {
    // ❌ VULNERABLE: this single shared slot is overwritten on every
    // outbid, regardless of whether the previous occupant ever
    // claimed their refund.
    env.storage().persistent().set(&DataKey::PendingReturnBidder, &prev_bidder);
    env.storage().persistent().set(&DataKey::PendingReturnAmount, &highest_bid);
}
```

## Secure Fix

```rust
// corrected version: a per-bidder mapping, not a single shared slot
#[contracttype]
pub enum DataKey {
    // ...
    PendingReturn(Address),
}

// in bid():
if let Some(prev_bidder) = prev_bidder {
    let key = DataKey::PendingReturn(prev_bidder.clone());
    let existing: i128 = env.storage().persistent().get(&key).unwrap_or(0);
    env.storage().persistent().set(&key, &(existing + highest_bid));
}

// in withdraw():
let key = DataKey::PendingReturn(caller.clone());
let amount: i128 = env.storage().persistent().get(&key).unwrap_or(0);
if amount == 0 {
    panic!("nothing to withdraw");
}
env.storage().persistent().set(&key, &0i128);
token::Client::new(&env, &token_id).transfer(&env.current_contract_address(), &caller, &amount);
```

Keying the refund by bidder address (and accumulating rather than
overwriting) guarantees every outbid bidder retains an independent,
permanently claimable entry regardless of how many further bids follow.

See [`secure/secure_escrow`](../../secure/secure_escrow) for the general
per-depositor escrow accounting pattern this fix follows, or apply the
`PendingReturn(Address)` mapping shown above directly to this contract.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
