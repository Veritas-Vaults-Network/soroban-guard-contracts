//! SECURE: Sequence-based Time Locks
//!
//! Uses ledger sequence numbers instead of timestamps for time-locks.
//! Sequences are strictly monotonically increasing and cannot be manipulated
//! by validators, unlike timestamps which have a drift window.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
    UnlockSequence(Address),
}

#[contract]
pub struct SequenceLockedVault;

#[contractimpl]
impl SequenceLockedVault {
    pub fn deposit(env: Env, user: Address, amount: i128, unlock_sequence: u32) {
        user.require_auth();
        let balance_key = DataKey::Balance(user.clone());
        let current: i128 = env.storage().persistent().get(&balance_key).unwrap_or(0);
        env.storage().persistent().set(&balance_key, &(current + amount));
        env.storage().persistent().set(&DataKey::UnlockSequence(user), &unlock_sequence);
    }

    /// SECURE: uses ledger sequence — immune to validator timestamp drift.
    pub fn withdraw(env: Env, user: Address) {
        user.require_auth();
        let unlock_sequence: u32 = env.storage()
            .persistent()
            .get(&DataKey::UnlockSequence(user.clone()))
            .unwrap();
        if env.ledger().sequence() < unlock_sequence {
            panic!("still locked"); // ✅ sequences cannot be manipulated
        }
        let balance_key = DataKey::Balance(user.clone());
        env.storage().persistent().set(&balance_key, &0i128);
        env.storage().persistent().remove(&DataKey::UnlockSequence(user));
    }

    pub fn balance(env: Env, user: Address) -> i128 {
        env.storage().persistent().get(&DataKey::Balance(user)).unwrap_or(0)
    }

    pub fn unlock_sequence(env: Env, user: Address) -> Option<u32> {
        env.storage().persistent().get(&DataKey::UnlockSequence(user))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::{Address as _, Ledger as _}, Address, Env};

    #[test]
    fn test_deposit_and_balance() {
        let env = Env::default();
        let id = env.register_contract(None, SequenceLockedVault);
        let client = SequenceLockedVaultClient::new(&env, &id);
        let alice = Address::generate(&env);
        env.mock_all_auths();
        client.deposit(&alice, &1000, &1000u32);
        assert_eq!(client.balance(&alice), 1000);
        assert_eq!(client.unlock_sequence(&alice), Some(1000u32));
    }

    #[test]
    fn test_withdrawal_after_lock_succeeds() {
        let env = Env::default();
        let id = env.register_contract(None, SequenceLockedVault);
        let client = SequenceLockedVaultClient::new(&env, &id);
        let alice = Address::generate(&env);
        env.mock_all_auths();
        client.deposit(&alice, &1000, &1000u32);
        env.ledger().set_sequence_number(1001);
        client.withdraw(&alice);
        assert_eq!(client.balance(&alice), 0);
    }

    #[test]
    #[should_panic(expected = "still locked")]
    fn test_withdrawal_before_lock_fails() {
        let env = Env::default();
        let id = env.register_contract(None, SequenceLockedVault);
        let client = SequenceLockedVaultClient::new(&env, &id);
        let alice = Address::generate(&env);
        env.mock_all_auths();
        client.deposit(&alice, &1000, &1000u32);
        env.ledger().set_sequence_number(999);
        client.withdraw(&alice);
    }
}
