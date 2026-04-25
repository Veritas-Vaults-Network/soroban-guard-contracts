# feat: Vulnerable flash loan with no repayment check

Implements the flash loan vulnerability described in [issue #34](https://github.com/Veritas-Vaults-Network/soroban-guard-contracts/issues/34).

A flash loan contract that transfers funds to a borrower and invokes their callback but never asserts that the borrowed amount was repaid within the same transaction, allowing permanent fund extraction.

## Vulnerable pattern

```rust
pub fn flash_loan(env: Env, borrower: Address, amount: i128) {
    // deduct from pool ...
    callback::BorrowerClient::new(&env, &borrower)
        .on_flash_loan(&env.current_contract_address(), &amount);
    // ❌ Missing: assert repayment was recorded
}
```

## Secure fix

```rust
let repaid = RepaymentLedgerClient::new(&env, &ledger).consume_repayment();
assert!(repaid >= amount, "flash loan not repaid");
```

## What's added

- `FlashLoanNoCheck` — lending contract with `flash_loan(borrower, amount)` that deducts from the pool and calls the borrower callback, but performs no repayment check afterward
- `RepaymentLedger` — neutral third-party contract used to record repayments without triggering Soroban's re-entry restriction
- `honest::HonestBorrower` — records repayment in the ledger during the callback
- `dishonest::DishonestBorrower` — does nothing, keeps the funds
- `secure::SecureFlashLoan` — reads the ledger after the callback and panics with `"flash loan not repaid"` if the full amount was not recorded

## Tests

| Test | Contract | Expected |
|---|---|---|
| `test_honest_borrower_repays` | Vulnerable | passes (borrower repaid) |
| `test_dishonest_borrower_drains_pool` | Vulnerable | passes — demonstrates the bug |
| `test_secure_honest_borrower_repays` | Secure | passes |
| `test_secure_dishonest_borrower_rejected` | Secure | panics with `flash loan not repaid` |

**Severity:** Critical

Closes #34
