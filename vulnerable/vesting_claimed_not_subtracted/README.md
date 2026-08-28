# `vulnerable/vesting_claimed_not_subtracted`

## Vulnerability: Vesting Claim Never Persists Its Running Total

**Severity:** Critical

## Description

`VestingClaimedNotSubtracted` is a linear vesting contract, structurally
identical to `secure/secure_vesting`, that pays a beneficiary out of a token
grant as it vests between a cliff ledger and an end ledger. `claim()`
correctly *computes* `claimable = vested - schedule.claimed` and transfers
exactly that amount to the beneficiary — the math is right. The bug is that
`claim()` never writes the updated `claimed` total back to persistent
storage: `schedule.claimed` is read, used to compute `claimable`, and then
discarded. The persisted schedule's `claimed` field is permanently stuck at
its initial value of `0`, no matter how many times `claim()` succeeds.

## Exploit Scenario

1. Admin creates a schedule for a beneficiary: `total = 1000`,
   `cliff_ledger = 0`, `end_ledger = 1000` (fully linear).
2. At ledger `500`, the schedule is 50% vested (`vested = 500`). The
   beneficiary calls `claim()` and correctly receives `500`.
3. The beneficiary calls `claim()` again immediately, at the *same* ledger
   sequence. Because `schedule.claimed` was never persisted, storage still
   reports `claimed = 0`, so `claimable = vested - 0 = 500` again — a second
   full payout of `500` for vesting that has already been paid.
4. The beneficiary repeats this an arbitrary number of times (or waits for
   full vesting and repeats there too), draining the contract's token
   balance far beyond their actual `1000`-token allocation — bounded only by
   how much the contract holds.

## Vulnerable Code

```rust
// see src/lib.rs
pub fn claim(env: Env, beneficiary: Address) -> i128 {
    beneficiary.require_auth();

    let key = DataKey::Schedule(beneficiary.clone());
    let schedule: VestingSchedule = env
        .storage()
        .persistent()
        .get(&key)
        .expect("schedule not found");

    let vested = Self::vested_for_schedule(&env, &schedule);
    let claimable = vested - schedule.claimed;
    if claimable <= 0 {
        panic!("nothing claimable");
    }

    // ❌ VULNERABLE: `schedule.claimed` is never advanced to `vested`,
    // and the schedule is never written back to storage.
    // schedule.claimed = vested;
    // env.storage().persistent().set(&key, &schedule);

    let token_id = get_token(&env);
    token::Client::new(&env, &token_id).transfer(
        &env.current_contract_address(),
        &beneficiary,
        &claimable,
    );

    claimable
}
```

## Secure Fix

```rust
// corrected version (see secure/secure_vesting)
pub fn claim(env: Env, beneficiary: Address) -> i128 {
    beneficiary.require_auth();

    let key = DataKey::Schedule(beneficiary.clone());
    let mut schedule: VestingSchedule = env
        .storage()
        .persistent()
        .get(&key)
        .expect("schedule not found");

    let vested = Self::vested_for_schedule(&env, &schedule);
    if vested <= schedule.claimed {
        panic!("nothing claimable");
    }

    let claimable = vested - schedule.claimed;
    schedule.claimed = vested;                      // ✅ advance the running total
    env.storage().persistent().set(&key, &schedule); // ✅ persist it before paying out

    let token_id = get_token(&env);
    token::Client::new(&env, &token_id).transfer(
        &env.current_contract_address(),
        &beneficiary,
        &claimable,
    );

    claimable
}
```

See [`secure/secure_vesting`](../../secure/secure_vesting) for the full
corrected implementation, which sets `schedule.claimed = vested` and writes
the schedule back to storage *before* returning, so a second claim at the
same vesting point correctly computes `claimable = 0` and panics with
`"nothing claimable"`.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
