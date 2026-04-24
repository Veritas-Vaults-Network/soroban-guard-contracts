# feat: Vulnerable no slippage protection in token swap

Implements the slippage vulnerability described in [issue #37](https://github.com/Veritas-Vaults-Network/soroban-guard-contracts/issues/37).

An AMM-style swap contract that accepts no `min_amount_out` parameter. An attacker can sandwich the victim's transaction — front-run to skew the pool price, let the victim's swap execute at the worse rate, then back-run to pocket the difference. The victim receives far fewer tokens than expected with no on-chain protection.

## Vulnerable pattern

```rust
pub fn swap(env: Env, user: Address, amount_in: i128) -> i128 {
    user.require_auth();
    let amount_out = calculate_out(&env, amount_in);
    // ❌ Missing: assert!(amount_out >= min_amount_out, "slippage exceeded");
    amount_out
}
```

## Secure fix

```rust
pub fn swap(env: Env, user: Address, amount_in: i128, min_amount_out: i128) -> i128 {
    user.require_auth();
    let amount_out = calculate_out(&env, amount_in);
    assert!(amount_out >= min_amount_out, "slippage exceeded"); // ✅
    apply_swap(&env, amount_in, amount_out);
    amount_out
}
```

## What's added

- `VulnerableAmm` — `swap(user, amount_in)` with constant-product pricing and no slippage guard
- `secure::SecureAmm` — `swap(user, amount_in, min_amount_out)` panics when output falls below the caller's threshold

## Tests

| Test | Contract | Expected |
|---|---|---|
| `test_normal_swap_returns_expected_amount` | Vulnerable | 100 A in → 90 B out |
| `test_manipulated_pool_returns_much_less_no_protection` | Vulnerable | attacker skews pool, victim gets <5 B, no panic |
| `test_secure_normal_swap_succeeds` | Secure | passes with `min_out=85` |
| `test_secure_rejects_manipulated_pool` | Secure | panics with `slippage exceeded` |

**Severity:** High

Closes #37
