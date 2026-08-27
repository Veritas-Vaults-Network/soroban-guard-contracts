# `vulnerable/vesting_cliff_after_end`

## Vulnerability: Missing Cliff-Before-End Validation in Vesting Schedule

**Severity:** High

## Description

`create_schedule` builds a linear vesting schedule from an admin-supplied
`cliff_ledger` and `end_ledger`, but only validates that `total > 0` — it
never checks that `cliff_ledger < end_ledger`. A plausible real-world
mistake (swapped function arguments, or a config file with the two fields
transposed) lets an admin create a schedule where the cliff comes *after*
the end. `vested_for_schedule`'s own math is unaffected and correct in
isolation; the flaw is entirely in the missing input validation upstream of
it.

## Exploit Scenario

1. Admin calls `create_schedule(beneficiary, 1_000, cliff_ledger=400,
   end_ledger=200)` — the cliff and end arguments are swapped.
2. The contract stores the schedule without checking `cliff_ledger <
   end_ledger`.
3. At ledger 200 — the date the grant was supposed to be fully vested — the
   first check in `vested_for_schedule` (`now < cliff_ledger`) is still
   true, so the beneficiary's vested amount is 0. Funds are locked far
   longer than promised.
4. At ledger 400 — the erroneous, later "cliff" — the second check
   (`now >= end_ledger`) is already true, so `vested_for_schedule` jumps
   straight to `schedule.total`. The beneficiary receives the entire
   allocation in one instant transfer via `claim()`, with zero gradual
   vesting ever having occurred — the "instant dump" risk linear vesting is
   meant to prevent.

## Vulnerable Code

```rust
// see src/lib.rs
pub fn create_schedule(
    env: Env,
    beneficiary: Address,
    total: i128,
    cliff_ledger: u32,
    end_ledger: u32,
) {
    Self::require_admin_auth(&env);
    if total <= 0 {
        panic!("total must be positive");
    }
    // ❌ Missing: if cliff_ledger >= end_ledger { panic!("invalid schedule") }

    let key = DataKey::Schedule(beneficiary);
    if env.storage().persistent().has(&key) {
        panic!("schedule already exists");
    }

    let schedule = VestingSchedule {
        total,
        claimed: 0,
        cliff_ledger,
        end_ledger,
    };
    env.storage().persistent().set(&key, &schedule);
}
```

## Secure Fix

```rust
// corrected version
pub fn create_schedule(
    env: Env,
    beneficiary: Address,
    total: i128,
    cliff_ledger: u32,
    end_ledger: u32,
) {
    Self::require_admin_auth(&env);
    if total <= 0 {
        panic!("total must be positive");
    }
    if cliff_ledger >= end_ledger {
        panic!("invalid schedule");
    }
    // ... store schedule as before
}
```

See [`secure/secure_vesting`](../../secure/secure_vesting) for the full
corrected implementation — its `create_schedule` includes exactly this
`if cliff_ledger >= end_ledger { panic!("invalid schedule") }` guard before
the schedule is ever stored.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
