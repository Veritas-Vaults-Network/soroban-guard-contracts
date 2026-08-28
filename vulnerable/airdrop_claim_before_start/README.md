# `vulnerable/airdrop_claim_before_start`

## Vulnerability: Missing Start-Time Check in Time-Gated Merkle Airdrop

**Severity:** Medium

## Description

`TimedAirdrop` is a merkle airdrop meant to be claimable only during a public
window `[start_time, end_time]`. The window exists so that a merkle root
(and every claimant's leaf data) can be prepared and distributed ahead of
time while still guaranteeing no one can actually claim before the
officially-announced public launch — e.g. before liquidity/price discovery
has been set up for everyone. `claim()` asserts `timestamp <= end_time` but
never asserts `timestamp >= start_time`, even though `start_time` is
faithfully stored at `initialize()` and exposed as if it were enforced. The
lower bound of the window simply does not exist at runtime.

## Exploit Scenario

1. The team computes the merkle root off-chain (necessarily before the
   public announcement, so leaves/proofs can be generated and distributed
   later) and calls `initialize()` with a `start_time` set to the announced
   public launch and `fund()`s the contract.
2. An insider, or a bot that reads the pending root/leaf data from the
   not-yet-publicized contract, already knows their `(claimant, amount)`
   pair and a valid proof.
3. That insider calls `claim()` immediately — long before `start_time` —
   with a valid proof and a timestamp that is still `<= end_time`. The
   missing lower-bound check means the call succeeds.
4. The insider receives (and can immediately act on/sell) tokens before the
   rest of the eligible public even has the ability to claim, defeating the
   fair-launch guarantee the time window was supposed to provide.

## Vulnerable Code

```rust
// see src/lib.rs
pub fn claim(env: Env, claimant: Address, amount: i128, proof: Vec<BytesN<32>>) {
    claimant.require_auth();
    assert!(!is_claimed(&env, &claimant), "already claimed");

    let end_time: u64 = env
        .storage()
        .persistent()
        .get(&DataKey::EndTime)
        .expect("not initialized");

    // ❌ VULNERABLE: start_time is stored but never checked here.
    // let start_time: u64 = env.storage().persistent().get(&DataKey::StartTime).unwrap();
    // assert!(env.ledger().timestamp() >= start_time, "airdrop has not started");
    assert!(env.ledger().timestamp() <= end_time, "airdrop has ended");

    verify_merkle_proof(&env, &claimant, amount, &proof);
    mark_claimed(&env, &claimant);
    // ... transfer ...
}
```

## Secure Fix

```rust
// corrected version
pub fn claim(env: Env, claimant: Address, amount: i128, proof: Vec<BytesN<32>>) {
    claimant.require_auth();
    assert!(!is_claimed(&env, &claimant), "already claimed");

    let start_time: u64 = env.storage().persistent().get(&DataKey::StartTime).unwrap();
    let end_time: u64 = env.storage().persistent().get(&DataKey::EndTime).unwrap();
    let now = env.ledger().timestamp();

    // ✅ Enforce BOTH bounds of the public claim window.
    assert!(now >= start_time, "airdrop has not started");
    assert!(now <= end_time, "airdrop has ended");

    verify_merkle_proof(&env, &claimant, amount, &proof);
    mark_claimed(&env, &claimant);
    // ... transfer ...
}
```

See [`secure/secure_airdrop`](../../secure/secure_airdrop) for the merkle-proof
verification pattern this crate reuses; the only change required to fix this
contract is adding the missing `now >= start_time` assertion above.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
