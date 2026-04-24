# feat: Vulnerable allowance not decremented after transfer_from

Implements the allowance vulnerability described in [issue #35](https://github.com/Veritas-Vaults-Network/soroban-guard-contracts/issues/35).

A token contract where `transfer_from` checks the spender's allowance but never decrements it after use, allowing the spender to reuse a single approval to drain the owner's full balance with repeated calls.

## Vulnerable pattern

```rust
pub fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
    spender.require_auth();
    let allowance = get_allowance(&env, &from, &spender);
    assert!(allowance >= amount, "insufficient allowance");
    // ❌ Missing: set_allowance(&env, &from, &spender, allowance - amount);
    do_transfer(&env, &from, &to, amount);
}
```

## Secure fix

```rust
set_allowance(&env, &from, &spender, allowance - amount); // ✅ decrement first
do_transfer(&env, &from, &to, amount);
```

## What's added

- `VulnerableToken` — `approve` + `transfer_from` with no allowance decrement
- `secure::SecureToken` — decrements allowance by `amount` before transferring

## Tests

| Test | Contract | Expected |
|---|---|---|
| `test_first_transfer_from_succeeds` | Vulnerable | passes |
| `test_second_transfer_from_reuses_allowance` | Vulnerable | passes — demonstrates the bug |
| `test_transfer_from_decrements_allowance` | Secure | passes, allowance is 0 after |
| `test_second_transfer_from_rejected` | Secure | panics with `insufficient allowance` |

**Severity:** Critical

Closes #35
