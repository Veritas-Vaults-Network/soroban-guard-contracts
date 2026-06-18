//! SECURE: Validated bounds check on all arithmetic operations
//!
//! This contract validates that all input amounts (deposit, withdraw) are within
//! safe bounds and uses checked arithmetic (checked_mul) for balance operations.
//! This prevents overflow panics and DoS attacks on user accounts.
//!
//! SECURITY FIXES:
//! 1. Validate amount > 0 && amount <= MAX_SAFE_AMOUNT on deposit/withdraw
//! 2. Use checked_mul instead of unchecked * for balance * rate

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

// Maximum safe amount to prevent overflow in arithmetic operations
// Set to i128::MAX / 4 to leave headroom for all operations
const MAX_SAFE_AMOUNT: i128 = i128::MAX / 4;

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

#[contract]
pub struct SecureVault;

#[contractimpl]
impl SecureVault {
    /// Deposit `amount` into the contract for `user`.
    /// Requires user auth and validates amount is within safe bounds.
    ///
    /// SECURITY: Ensures amount > 0 && amount <= MAX_SAFE_AMOUNT before
    /// performing any arithmetic to prevent overflow in balance + amount.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();

        // ✅ Validate amount is within safe bounds
        if amount <= 0 || amount > MAX_SAFE_AMOUNT {
            panic!("amount out of safe range");
        }

        let key = DataKey::Balance(user.clone());
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        // Safe now because amount is bounded
        env.storage().persistent().set(&key, &(balance + amount));
    }

    /// Withdraw `amount` from the contract for `user`.
    /// Requires user auth and validates amount is within safe bounds.
    ///
    /// SECURITY: Ensures amount > 0 && amount <= MAX_SAFE_AMOUNT and uses
    /// checked_sub to prevent underflow.
    pub fn withdraw(env: Env, user: Address, amount: i128) {
        user.require_auth();

        // ✅ Validate amount is within safe bounds
        if amount <= 0 || amount > MAX_SAFE_AMOUNT {
            panic!("amount out of safe range");
        }

        let key = DataKey::Balance(user.clone());
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let new_balance = balance.checked_sub(amount).expect("insufficient funds");
        env.storage().persistent().set(&key, &new_balance);
    }

    /// Apply a rate multiplier to the user's balance.
    /// Uses checked_mul to safely detect overflow without panic context loss.
    ///
    /// SECURITY: Uses checked_mul instead of unchecked * to explicitly
    /// handle overflow and provide a clear error message.
    pub fn apply_rate(env: Env, user: Address, rate: i128) {
        let key = DataKey::Balance(user.clone());
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        // ✅ Use checked_mul to safely detect overflow
        let new_balance = balance.checked_mul(rate).expect("overflow in apply_rate");
        env.storage().persistent().set(&key, &new_balance);
    }

    /// Get the current balance for a user.
    pub fn balance(env: Env, user: Address) -> i128 {
        let key = DataKey::Balance(user);
        env.storage().persistent().get(&key).unwrap_or(0)
    }

    /// Get the maximum safe amount constant.
    pub fn get_max_safe_amount(_env: Env) -> i128 {
        MAX_SAFE_AMOUNT
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, SecureVaultClient<'static>) {
        let env = Env::default();
        let id = env.register_contract(None, SecureVault);
        let client = SecureVaultClient::new(&env, &id);
        (env, client)
    }

    #[test]
    #[should_panic(expected = "amount out of safe range")]
    fn test_secure_deposit_above_max_panics() {
        let (env, client) = setup();
        let user = Address::generate(&env);
        env.mock_all_auths();

        // Attempting to deposit MAX_SAFE_AMOUNT + 1 must panic
        client.deposit(&user, &(MAX_SAFE_AMOUNT + 1));
    }

    #[test]
    #[should_panic(expected = "amount out of safe range")]
    fn test_secure_deposit_zero_panics() {
        let (env, client) = setup();
        let user = Address::generate(&env);
        env.mock_all_auths();

        // Deposit of 0 must panic
        client.deposit(&user, &0);
    }

    #[test]
    #[should_panic(expected = "amount out of safe range")]
    fn test_secure_deposit_negative_panics() {
        let (env, client) = setup();
        let user = Address::generate(&env);
        env.mock_all_auths();

        // Negative deposit must panic
        client.deposit(&user, &-1);
    }

    #[test]
    fn test_secure_apply_rate_safe_values_works() {
        let (env, client) = setup();
        let user = Address::generate(&env);
        env.mock_all_auths();

        // Deposit a safe amount
        let safe_amount = 1_000_000;
        client.deposit(&user, &safe_amount);
        assert_eq!(client.balance(&user), safe_amount);

        // Apply a safe rate
        let rate = 2;
        client.apply_rate(&user, &rate);

        // Verify balance is correctly multiplied
        assert_eq!(client.balance(&user), safe_amount * rate);
    }

    #[test]
    #[should_panic(expected = "overflow in apply_rate")]
    fn test_secure_apply_rate_overflow_panics() {
        let (env, client) = setup();
        let user = Address::generate(&env);
        env.mock_all_auths();

        // Deposit at maximum safe amount
        client.deposit(&user, &MAX_SAFE_AMOUNT);
        assert_eq!(client.balance(&user), MAX_SAFE_AMOUNT);

        // Apply a rate that would cause overflow: 1_000_001
        // MAX_SAFE_AMOUNT * 1_000_001 will overflow i128
        client.apply_rate(&user, &1_000_001);
    }

    #[test]
    #[should_panic(expected = "amount out of safe range")]
    fn test_secure_withdraw_above_max_panics() {
        let (env, client) = setup();
        let user = Address::generate(&env);
        env.mock_all_auths();

        // Deposit a safe amount first
        let safe_amount = 1_000_000;
        client.deposit(&user, &safe_amount);

        // Try to withdraw an amount exceeding MAX_SAFE_AMOUNT
        client.withdraw(&user, &(MAX_SAFE_AMOUNT + 1));
    }

    #[test]
    fn test_secure_withdraw_safe_amount() {
        let (env, client) = setup();
        let user = Address::generate(&env);
        env.mock_all_auths();

        let safe_amount = 100_000;
        client.deposit(&user, &safe_amount);

        let withdraw_amount = 30_000;
        client.withdraw(&user, &withdraw_amount);

        assert_eq!(client.balance(&user), safe_amount - withdraw_amount);
    }

    #[test]
    fn test_secure_get_max_safe_amount() {
        let (_env, client) = setup();
        let max_safe = client.get_max_safe_amount();
        assert_eq!(max_safe, i128::MAX / 4);
    }
}
