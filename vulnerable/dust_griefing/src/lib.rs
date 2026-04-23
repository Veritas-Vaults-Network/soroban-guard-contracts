//! VULNERABLE: Dust Griefing via No Minimum Deposit
//!
//! A vault contract where `deposit()` accepts any positive amount, including 1.
//! An attacker can create thousands of 1-unit deposits across many accounts,
//! bloating persistent storage and increasing TTL extension costs for all users.
//!
//! VULNERABILITY: Missing minimum deposit threshold check.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

#[contract]
pub struct DustGriefingContract;

#[contractimpl]
impl DustGriefingContract {
    /// VULNERABLE: accepts any amount ≥ 1, including dust amounts that bloat storage.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        // ❌ Missing: assert!(amount >= MIN_DEPOSIT, "below minimum");
        let key = DataKey::Balance(user);
        let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(bal + amount));
    }

    pub fn balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, DustGriefingContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, DustGriefingContract);
        let client = DustGriefingContractClient::new(&env, &id);
        (env, client)
    }

    #[test]
    fn test_normal_deposit_works() {
        let (env, client) = setup();
        let user = Address::generate(&env);
        client.deposit(&user, &1_000_000);
        assert_eq!(client.balance(&user), 1_000_000);
    }

    /// Demonstrates the vulnerability: a dust deposit of 1 unit is accepted.
    #[test]
    fn test_dust_deposit_succeeds() {
        let (env, client) = setup();
        let attacker = Address::generate(&env);
        // ❌ 1-unit deposit succeeds — attacker can repeat this across thousands
        // of addresses to bloat persistent storage.
        client.deposit(&attacker, &1);
        assert_eq!(client.balance(&attacker), 1);
    }

    // ── secure version ──────────────────────────────────────────────────────

    #[test]
    fn test_secure_normal_deposit_works() {
        use crate::secure::SecureVaultClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureVault);
        let client = SecureVaultClient::new(&env, &id);

        let user = Address::generate(&env);
        client.deposit(&user, &1_000_000);
        assert_eq!(client.balance(&user), 1_000_000);
    }

    /// ✅ Secure version rejects dust deposits below MIN_DEPOSIT.
    #[test]
    #[should_panic(expected = "below minimum deposit")]
    fn test_secure_rejects_dust() {
        use crate::secure::SecureVaultClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureVault);
        let client = SecureVaultClient::new(&env, &id);

        let user = Address::generate(&env);
        client.deposit(&user, &1);
    }
}
