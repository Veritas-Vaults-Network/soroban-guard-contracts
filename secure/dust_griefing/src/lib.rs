//! SECURE: Vault with minimum deposit threshold
//!
//! This is the fixed mirror of `dust_griefing`.
//!
//! FIX APPLIED:
//! Deposits below `MIN_DEPOSIT` are rejected, preventing attackers from
//! creating thousands of 1-unit storage entries that bloat persistent storage
//! and inflate TTL extension costs for legitimate users.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

const MIN_DEPOSIT: i128 = 1_000;

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

fn get_balance(env: &Env, user: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Balance(user.clone()))
        .unwrap_or(0)
}

fn set_balance(env: &Env, user: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Balance(user.clone()), &amount);
}

#[contract]
pub struct SecureDustGriefingVault;

#[contractimpl]
impl SecureDustGriefingVault {
    /// SECURE: rejects deposits below MIN_DEPOSIT, preventing dust griefing.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        // ✅ FIX: enforce minimum deposit to prevent storage bloat
        assert!(amount >= MIN_DEPOSIT, "below minimum deposit");
        let bal = get_balance(&env, &user);
        set_balance(&env, &user, bal + amount);
    }

    pub fn balance(env: Env, user: Address) -> i128 {
        get_balance(&env, &user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    #[test]
    fn test_normal_deposit_works() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureDustGriefingVault);
        let client = SecureDustGriefingVaultClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        env.mock_all_auths();
        client.deposit(&alice, &1_000_000);
        assert_eq!(client.balance(&alice), 1_000_000);
    }

    /// Secure version rejects amounts below MIN_DEPOSIT.
    #[test]
    #[should_panic(expected = "below minimum deposit")]
    fn test_dust_deposit_rejected() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureDustGriefingVault);
        let client = SecureDustGriefingVaultClient::new(&env, &contract_id);

        let attacker = Address::generate(&env);
        env.mock_all_auths();
        // ✅ This panics — dust deposit is rejected
        client.deposit(&attacker, &1);
    }

    #[test]
    fn test_deposit_at_minimum_works() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureDustGriefingVault);
        let client = SecureDustGriefingVaultClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        env.mock_all_auths();
        client.deposit(&alice, &MIN_DEPOSIT);
        assert_eq!(client.balance(&alice), MIN_DEPOSIT);
    }
}
