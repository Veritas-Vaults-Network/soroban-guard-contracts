# `vulnerable/single_approval_escrow_release`

## Vulnerability: Hardcoded Multisig Approval Threshold

**Severity:** Critical

## Description

This is a marketplace escrow where a buyer deposits funds for a seller, and
release is meant to require a configurable N-of-M threshold of independent
arbiters to approve (e.g. 2-of-3), so that no single arbiter can unilaterally
move the buyer's funds. `initialize` correctly validates the threshold
(`1 <= threshold <= arbiters.len()`) and `approve_release` correctly records
each arbiter's approval exactly once — the configuration and bookkeeping
layers are both implemented correctly. The bug is isolated entirely to
`release()`, which checks `Approvals.len() < 1` instead of comparing against
the stored `Threshold`. This reads like leftover logic from an earlier,
single-approver draft of the contract that was never updated when N-of-M
multisig support was added.

## Exploit Scenario

1. A buyer initializes an escrow for 1000 tokens naming 3 arbiters and a
   threshold of 2 (2-of-3 consensus required to release funds).
2. A single arbiter — compromised, bribed, or simply malicious — calls
   `approve_release()`. `approval_count()` is now 1, still below the
   configured `get_threshold()` of 2.
3. Anyone calls `release()`. The contract checks `Approvals.len() < 1`
   (`1 < 1` is false) instead of `Approvals.len() < Threshold` (`1 < 2` is
   true), so the check passes and the full 1000 tokens are transferred to
   the seller — despite only one of the required two arbiters ever
   approving.

## Vulnerable Code

```rust
// see src/lib.rs
pub fn release(env: Env) {
    // ...
    let approvals: Vec<Address> = env
        .storage()
        .persistent()
        .get(&DataKey::Approvals)
        .unwrap_or_else(|| Vec::new(&env));

    // ❌ VULNERABLE: should compare against the stored `Threshold`, not
    // a hardcoded `1`.
    if approvals.len() < 1 {
        panic!("insufficient approvals");
    }
    // ... transfer funds to seller
}
```

## Secure Fix

```rust
// corrected version
pub fn release(env: Env) {
    // ...
    let approvals: Vec<Address> = env
        .storage()
        .persistent()
        .get(&DataKey::Approvals)
        .unwrap_or_else(|| Vec::new(&env));
    let threshold: u32 = env
        .storage()
        .persistent()
        .get(&DataKey::Threshold)
        .expect("not initialized");

    // ✅ Compare against the configured threshold, not a hardcoded constant.
    if approvals.len() < threshold {
        panic!("insufficient approvals");
    }
    // ... transfer funds to seller
}
```

See the inline test module in `src/lib.rs` for a working proof-of-concept
(`test_single_arbiter_releases_escrow_despite_two_of_three_threshold_bug`),
since no separate `secure/` mirror crate exists for this contract.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
