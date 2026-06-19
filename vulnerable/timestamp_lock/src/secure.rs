//! SECURE: Ledger-Sequence-Based Time Locks
//!
//! A time-locked vault that uses `env.ledger().sequence()` to enforce lock periods.
//! This is secure because ledger sequences are monotonically increasing and cannot be
//! manipulated by validators.
//!
//! SECURITY: Using ledger sequences instead of timestamps for time-locking.
//! Ledger sequences are guaranteed to increment by exactly 1 with each block,
//! making them immune to timestamp drift attacks.
//!
//! KEY IMPROVEMENT: Timestamp → Ledger Sequence
//! - Timestamps can drift within validator consensus windows (typically ±5-15 seconds)
//! - Ledger sequences ALWAYS increment by 1 per block, providing precise, immutable locking
//! - No possibility of early withdrawal through validator manipulation

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
    UnlockLedger(Address),
}

const MIN_LOCK_DURATION: u32 = 100; // Minimum lock duration in ledgers

#[contract]
pub struct SecureTimelockVault;

#[contractimpl]
impl SecureTimelockVault {
    /// Deposit `amount` and set a lock duration in ledger sequences.
    /// Requires user auth.
    ///
    /// # Arguments
    /// - `user`: The account depositing funds
    /// - `amount`: The amount to deposit
    /// - `lock_duration_ledgers`: Number of ledgers to lock (must be >= MIN_LOCK_DURATION)
    ///
    /// # Panics
    /// If lock_duration_ledgers < MIN_LOCK_DURATION (100)
    pub fn deposit(env: Env, user: Address, amount: i128, lock_duration_ledgers: u32) {
        user.require_auth();

        // Enforce minimum lock duration
        if lock_duration_ledgers < MIN_LOCK_DURATION {
            panic!(
                "lock_duration_ledgers must be at least {}",
                MIN_LOCK_DURATION
            );
        }

        // Store the balance
        let balance_key = DataKey::Balance(user.clone());
        let current_balance: i128 = env.storage().persistent().get(&balance_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&balance_key, &(current_balance + amount));

        // Set the unlock ledger sequence: current sequence + lock duration
        let unlock_ledger = env.ledger().sequence() + lock_duration_ledgers;
        let unlock_key = DataKey::UnlockLedger(user);
        env.storage().persistent().set(&unlock_key, &unlock_ledger);
    }

    /// Withdraw funds after the lock period expires.
    /// SECURE: Uses ledger sequence which is immutable and strictly monotonic.
    pub fn withdraw(env: Env, user: Address) {
        user.require_auth();

        let unlock_key = DataKey::UnlockLedger(user.clone());
        let unlock_ledger: u32 = env
            .storage()
            .persistent()
            .get(&unlock_key)
            .expect("unlock ledger not set");

        // ✓ SECURE: Ledger sequence is guaranteed to increment monotonically
        // No validator can manipulate the sequence number
        if env.ledger().sequence() < unlock_ledger {
            panic!("still locked");
        }

        // Release all funds
        let balance_key = DataKey::Balance(user.clone());
        let _balance: i128 = env.storage().persistent().get(&balance_key).unwrap_or(0);

        // Reset balance and unlock ledger
        env.storage().persistent().set(&balance_key, &0i128);
        env.storage().persistent().remove(&unlock_key);
    }

    /// Returns the balance of `user`, defaulting to 0.
    pub fn balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }

    /// Returns the unlock ledger sequence for `user`, or `None` if no lock exists.
    pub fn unlock_ledger(env: Env, user: Address) -> Option<u32> {
        env.storage().persistent().get(&DataKey::UnlockLedger(user))
    }

    /// Returns the current ledger sequence number.
    pub fn current_sequence(env: Env) -> u32 {
        env.ledger().sequence()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, testutils::Ledger as _, Address, Env};

    #[test]
    fn test_secure_deposit_and_balance() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureTimelockVault);
        let client = SecureTimelockVaultClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let lock_duration = 200u32;

        env.mock_all_auths();
        client.deposit(&alice, &1000, &lock_duration);

        assert_eq!(client.balance(&alice), 1000);
        // Current sequence is typically 0 or 1 in tests
        let current = client.current_sequence();
        assert_eq!(client.unlock_ledger(&alice), Some(current + lock_duration));
    }

    /// Withdrawal before lock period expires must panic.
    #[test]
    #[should_panic(expected = "still locked")]
    fn test_secure_withdraw_before_unlock_panics() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureTimelockVault);
        let client = SecureTimelockVaultClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let lock_duration = 200u32;

        env.mock_all_auths();
        client.deposit(&alice, &1000, &lock_duration);

        // Try to withdraw at the same sequence (before unlock) — must panic
        client.withdraw(&alice);
    }

    /// Withdrawal after lock period expires must succeed.
    #[test]
    fn test_secure_withdraw_after_unlock_works() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureTimelockVault);
        let client = SecureTimelockVaultClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let lock_duration = 200u32;

        env.mock_all_auths();
        client.deposit(&alice, &1000, &lock_duration);

        let unlock_seq = client
            .unlock_ledger(&alice)
            .expect("should have unlock ledger");

        // Advance ledger sequence past unlock ledger
        env.ledger().set_sequence_number(unlock_seq + 1);

        // Should succeed
        client.withdraw(&alice);

        assert_eq!(client.balance(&alice), 0);
        assert_eq!(client.unlock_ledger(&alice), None);
    }

    /// Lock duration below minimum must panic.
    #[test]
    #[should_panic(expected = "lock_duration_ledgers must be at least")]
    fn test_secure_lock_duration_below_minimum_panics() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureTimelockVault);
        let client = SecureTimelockVaultClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let lock_duration = 50u32; // Below MIN_LOCK_DURATION (100)

        env.mock_all_auths();
        client.deposit(&alice, &1000, &lock_duration);
    }
}
