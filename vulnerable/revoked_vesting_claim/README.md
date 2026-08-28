# `vulnerable/revoked_vesting_claim`

## Vulnerability: Revoked Vesting Claim (Revocation Doesn't Stop the Vesting Curve)

**Severity:** High

## Description

This contract implements revocable token vesting and is deliberately built as a near line-for-line copy of the corrected reference implementation, `secure/secure_vesting`, so the regression is easy to miss in review. `revoke()` is correct: it computes the unvested balance at the moment of revocation (`total - vested_now`) and credits it to `TreasuryBalance`, then stamps `schedule.revoked_at`. The bug is that nothing downstream ever looks at `revoked_at` again. `vested_for_schedule()` computes vesting purely from `env.ledger().sequence()` with no cap at the revocation ledger, and `claim()` never checks `schedule.revoked_at.is_some()` before paying out. A "revoked" beneficiary's vesting curve keeps running exactly as if `revoke()` had never been called, so once the ledger sequence passes `end_ledger` they can still claim their entire original `total` grant — on top of the unvested portion the admin already reclaimed to the treasury's bookkeeping balance. The same tokens are promised twice, leaving the contract insolvent relative to what was ever funded for that grant.

## Exploit Scenario

1. Admin creates a vesting schedule for a beneficiary: `total = 1000`, `cliff_ledger = 200`, `end_ledger = 400`, and funds the contract with 1000 tokens.
2. At ledger 250 the admin calls `revoke(beneficiary)`. Vested-so-far is `1000 * (250-200)/(400-200) = 250`, so `unvested = 750` is correctly credited to `TreasuryBalance`. `schedule.revoked_at` is set to `250`.
3. Ledger sequence advances past `end_ledger` (e.g. to 500). The beneficiary calls `claim(beneficiary)`.
4. `claim()` never checks `revoked_at`, and `vested_for_schedule()` sees `now (500) >= end_ledger (400)` and returns the full `total` (1000), ignoring the revocation entirely. The beneficiary is paid the full 1000 tokens.
5. Result: `treasury_balance() (750) + beneficiary payout (1000) = 1750`, which is 75% more than the 1000 tokens ever funded for this single grant — the contract is insolvent.

## Vulnerable Code

```rust
// claim() never checks schedule.revoked_at before paying out:
pub fn claim(env: Env, beneficiary: Address) -> i128 {
    beneficiary.require_auth();
    let mut schedule: VestingSchedule = /* ... load schedule ... */;
    // ❌ Missing: panic!("schedule revoked") when schedule.revoked_at.is_some()
    let vested = Self::vested_for_schedule(&env, &schedule);
    let claimable = vested - schedule.claimed;
    schedule.claimed = vested;
    // ...transfer claimable to beneficiary...
    claimable
}

// vested_for_schedule() never caps `now` at revoked_at:
fn vested_for_schedule(env: &Env, schedule: &VestingSchedule) -> i128 {
    let now = env.ledger().sequence();
    // ❌ Missing: cap `now` at schedule.revoked_at when it is Some
    if now >= schedule.end_ledger {
        return schedule.total;
    }
    // ...linear interpolation...
}
```

## Secure Fix

See [`secure/secure_vesting`](../../secure/secure_vesting) for the full corrected implementation. The two missing checks are:

```rust
// claim(): reject any claim on a revoked schedule.
if schedule.revoked_at.is_some() {
    panic!("schedule revoked");
}

// vested_for_schedule(): cap the effective "now" at the revocation ledger,
// so vesting actually stops once revoke() has run.
let effective_now = match schedule.revoked_at {
    Some(revoked_at) if now > revoked_at => revoked_at,
    _ => now,
};
```

With both checks in place, `revoke()`'s treasury bookkeeping and the beneficiary's maximum possible payout stay consistent: the beneficiary can never claim more than `vested_for_schedule` at the revocation ledger, and `treasury_balance + beneficiary_payout` can never exceed `total`.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
