# `vulnerable/airdrop_expiry_ignored`

## Vulnerability: Airdrop Expiry Ignored

**Severity:** Medium

## Description

`ExpiringAirdrop` is documented to close at an `end_time` set during
`initialize`, after which the admin calls `sweep_unclaimed()` to return any
leftover pool balance to a treasury address. `sweep_unclaimed()` correctly
requires `env.ledger().timestamp() > end_time` before it will run, but
`claim()` never checks `end_time` at all. The result is an airdrop that never
actually closes: valid proofs are accepted forever, regardless of the
advertised deadline, and regardless of whether the admin has already swept
the pool believing the campaign was over.

## Exploit Scenario

1. Admin initializes the airdrop with `end_time = T`, funds the pool, and
   publicly advertises that claims close at `T`.
2. Ledger time passes `T`. Believing the campaign is over, the admin calls
   `sweep_unclaimed()`, which correctly passes its `end_time` check and
   transfers the entire remaining contract balance to the treasury.
3. A claimant with a valid Merkle proof who never claimed before `T` calls
   `claim()` at any point afterward — `claim()` has no expiry check, so it
   passes every guard it does have (not-already-claimed, valid proof) and
   only fails when the token transfer hits an empty contract balance,
   producing a confusing panic instead of a clean "airdrop expired"
   rejection. If the admin had instead only partially swept, or re-funded the
   contract for another purpose, the same missing check lets the late claim
   *succeed*, silently drawing down funds the admin believed were already
   accounted for elsewhere.

## Vulnerable Code

```rust
// see src/lib.rs
pub fn claim(env: Env, claimant: Address, amount: i128, proof: Vec<BytesN<32>>) {
    claimant.require_auth();
    assert!(!is_claimed(&env, &claimant), "already claimed");

    // ❌ VULNERABLE: no check against DataKey::EndTime here at all.

    verify_merkle_proof(&env, &claimant, amount, &proof);

    mark_claimed(&env, &claimant);

    let token: Address = env.storage().persistent().get(&DataKey::Token).unwrap();
    token::Client::new(&env, &token).transfer(
        &env.current_contract_address(),
        &claimant,
        &amount,
    );

    env.events()
        .publish((symbol_short!("claim"),), (claimant, amount));
}
```

## Secure Fix

```rust
// corrected version
pub fn claim(env: Env, claimant: Address, amount: i128, proof: Vec<BytesN<32>>) {
    claimant.require_auth();
    assert!(!is_claimed(&env, &claimant), "already claimed");

    // ✅ Enforce the same deadline that sweep_unclaimed() enforces.
    let end_time: u64 = env
        .storage()
        .persistent()
        .get(&DataKey::EndTime)
        .expect("not initialized");
    assert!(env.ledger().timestamp() <= end_time, "airdrop expired");

    verify_merkle_proof(&env, &claimant, amount, &proof);

    mark_claimed(&env, &claimant);

    let token: Address = env.storage().persistent().get(&DataKey::Token).unwrap();
    token::Client::new(&env, &token).transfer(
        &env.current_contract_address(),
        &claimant,
        &amount,
    );

    env.events()
        .publish((symbol_short!("claim"),), (claimant, amount));
}
```

Mirroring `sweep_unclaimed()`'s `end_time` check inside `claim()` closes the
window: once the airdrop is past its documented close time, claims fail
cleanly with `"airdrop expired"` instead of racing an admin sweep.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
