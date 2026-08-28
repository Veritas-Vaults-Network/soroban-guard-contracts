# `vulnerable/epoch_claim_no_advance`

## Vulnerability: Epoch-Advance Keeper Missing a Time Guard

**Severity:** Critical

## Description

`EpochStaking` is an epoch-based staking reward distributor that uses the
standard MasterChef-style `reward_per_share` accumulator: a fixed amount of
reward is meant to be added to the pool once per epoch via a permissionless
keeper function, `advance_epoch()`. Letting anyone call `advance_epoch()` is
an intentional, common design choice — the function is only supposed to
*reflect* the passage of real time, not create value, so it needs no access
control. The bug is that `advance_epoch()` never actually checks that any
time has passed since it was last called. It only guards against dividing by
zero (`require TotalStaked > 0`) before unconditionally adding one full
epoch's worth of reward to the accumulator. Because there is no
`require(now >= last_advance_time + epoch_length)`-style gate, the function
can be called an unbounded number of times back-to-back, within a single
ledger/transaction, with zero real time elapsing between calls.

## Exploit Scenario

1. A staker deposits into the pool, as normal.
2. Instead of waiting for one real epoch to elapse, the staker (or anyone
   else, since `advance_epoch()` requires no auth) calls `advance_epoch()`
   in a tight loop — e.g. 50 times in the same transaction or block, with the
   ledger timestamp unchanged.
3. Each call unconditionally adds a full epoch's worth of reward to
   `RewardPerShare`, since nothing checks how much real time elapsed since
   the previous call.
4. The staker calls `claim()` and receives 50 epochs' worth of reward
   immediately, instead of the single epoch that actually passed — draining
   the funded reward pool far faster than the epoch schedule intends.

## Vulnerable Code

```rust
// see src/lib.rs
pub fn advance_epoch(env: Env) {
    let total_staked = get_total_staked(&env);
    assert!(total_staked > 0, "no stakers");

    // ❌ VULNERABLE: no timestamp/sequence check of any kind here.
    // let last = get_last_advance_time(&env);
    // let epoch_length = get_epoch_length(&env);
    // assert!(env.ledger().timestamp() >= last + epoch_length, "epoch not elapsed");
    // set_last_advance_time(&env, env.ledger().timestamp());

    let delta = get_epoch_reward_amount(&env) * PRECISION / total_staked;
    set_reward_per_share(&env, get_reward_per_share(&env) + delta);
}
```

## Secure Fix

```rust
// corrected version
pub fn advance_epoch(env: Env) {
    let total_staked = get_total_staked(&env);
    assert!(total_staked > 0, "no stakers");

    let now = env.ledger().timestamp();
    let last = get_last_advance_time(&env);
    let epoch_length = get_epoch_length(&env);
    assert!(now >= last + epoch_length, "epoch not elapsed");
    set_last_advance_time(&env, now);

    let delta = get_epoch_reward_amount(&env) * PRECISION / total_staked;
    set_reward_per_share(&env, get_reward_per_share(&env) + delta);
}
```

See the inline `secure` variant described above (this crate has no separate
`secure/` mirror) for the corrected implementation: persist
`LastAdvanceTime` and `EpochLength`, and require that at least one full
epoch's worth of real time has elapsed since the last successful advance
before mutating `RewardPerShare`.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
