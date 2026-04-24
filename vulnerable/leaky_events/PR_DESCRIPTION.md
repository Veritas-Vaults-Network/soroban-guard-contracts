# feat: Vulnerable contract emits events with sensitive balance data

Implements the privacy vulnerability described in [issue #36](https://github.com/Veritas-Vaults-Network/soroban-guard-contracts/issues/36).

A token contract that publishes post-transfer balances for both sender and recipient in every transfer event. Off-chain indexers and anyone monitoring the ledger can reconstruct every account's full transaction history and current balance from the event stream alone — no storage access required.

## Vulnerable pattern

```rust
env.events().publish(
    (symbol_short!("transfer"),),
    (from.clone(), to.clone(), new_from_balance, new_to_balance), // ❌ leaks balances
);
```

## Secure fix

```rust
env.events().publish(
    (symbol_short!("transfer"),),
    (from.clone(), to.clone(), amount), // ✅ amount only
);
```

## What's added

- `VulnerableToken` — emits `(from, to, new_from_balance, new_to_balance)` on every transfer
- `secure::SecureToken` — emits only `(from, to, amount)`, keeping balances private

## Tests

| Test | Contract | Expected |
|---|---|---|
| `test_transfer_emits_balance_values` | Vulnerable | event tuple has 4 fields including leaked post-transfer balances |
| `test_secure_transfer_emits_only_amount` | Secure | event tuple has 3 fields, transfer amount only |

**Severity:** Low (privacy)

Closes #36
