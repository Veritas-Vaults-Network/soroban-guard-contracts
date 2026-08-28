# `vulnerable/collateral_withdraw_no_health_check`

## Vulnerability: Collateral Withdrawal Without Health Check

**Severity:** Critical  
**Category:** DeFi / Lending Pool

## Description

A collateralized lending protocol requires borrowers to maintain a minimum collateral-to-debt ratio (governed by `max_ltv_bps`). While `borrow()` enforces that the new debt is backed by the user's deposited collateral, `withdraw_collateral()` only checks that the user has enough deposited collateral (`current >= amount`) without verifying that their **remaining collateral** is sufficient to back their active outstanding debt.

An attacker can deposit collateral, borrow up to the maximum allowable debt, and immediately withdraw 100% of their deposited collateral. The attacker walks away with the borrowed funds while leaving unbacked bad debt in the protocol.

## Exploit Scenario

1. Protocol initializes with collateral priced at $2.00/unit and a 75% max LTV limit.
2. Attacker deposits 1,000 collateral units (worth $2,000 USD).
3. Attacker borrows $1,500 USD (the maximum allowed at 75% LTV).
4. Attacker calls `withdraw_collateral(1000)`.
5. The vulnerable contract processes the withdrawal because `collateral >= 1000`, failing to verify whether remaining collateral can support the $1,500 debt.
6. Attacker walks away with $1,500 USD while the protocol holds $0 collateral against $1,500 of bad debt.

## Vulnerable Code

```rust
pub fn withdraw_collateral(env: Env, user: Address, amount: i128) {
    user.require_auth();
    assert!(amount > 0, "amount must be positive");

    let current: i128 = env
        .storage()
        .persistent()
        .get(&DataKey::Collateral(user.clone()))
        .unwrap_or(0);
    assert!(current >= amount, "insufficient collateral balance");

    // ❌ VULNERABILITY: No health check on remaining collateral!
    let new_collateral = current.checked_sub(amount).expect("underflow");
    env.storage()
        .persistent()
        .set(&DataKey::Collateral(user.clone()), &new_collateral);

    env.events()
        .publish((symbol_short!("withdraw"), user), amount);
}
```

## Secure Fix

```rust
// ✅ FIX: Calculate remaining collateral and verify it covers active debt
let remaining_collateral = current.checked_sub(amount).expect("underflow");
let debt: i128 = env
    .storage()
    .persistent()
    .get(&DataKey::Debt(user.clone()))
    .unwrap_or(0);

if debt > 0 {
    let remaining_value_usd =
        remaining_collateral.checked_mul(price).expect("overflow") / 1_000_000;
    let max_supported_debt =
        remaining_value_usd.checked_mul(ltv_bps as i128).expect("overflow") / 10_000;

    assert!(
        debt <= max_supported_debt,
        "health check failed: remaining collateral cannot cover debt"
    );
}

env.storage()
    .persistent()
    .set(&DataKey::Collateral(user.clone()), &remaining_collateral);
```

See [`src/secure.rs`](src/secure.rs) for the complete secure implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md#38-collateral-withdrawal-without-health-check-collateral_withdraw_no_health_check)
- [docs/threat_model.md](../../docs/threat_model.md)
