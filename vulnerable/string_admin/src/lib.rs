//! VULNERABLE: Admin Stored as String Instead of Address
//!
//! A contract that stores the admin as a `String` and authenticates callers
//! with a plain `==` comparison. String comparison provides no cryptographic
//! guarantee — any caller who knows (or guesses) the stored string value can
//! pass the check without holding the corresponding private key.
//!
//! VULNERABILITY: `String` comparison instead of `Address::require_auth()`.
//! SECURE MIRROR: `SecureConfigContract` stores admin as `Address` and calls
//!                `admin.require_auth()`.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String};

#[contracttype]
pub enum DataKey {
    Admin,
    Config,
}

// ---------------------------------------------------------------------------
// Vulnerable contract
// ---------------------------------------------------------------------------

#[contract]
pub struct ConfigContract;

#[contractimpl]
impl ConfigContract {
    pub fn initialize(env: Env, admin: String) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// VULNERABLE: authenticates by comparing caller-supplied string to the
    /// stored admin string. No cryptographic proof is required.
    pub fn set_config(env: Env, caller: String, new_value: u32) {
        let admin: String = env.storage().persistent().get(&DataKey::Admin).unwrap();
        // ❌ String comparison — no cryptographic auth
        if caller != admin {
            panic!("not admin");
        }
        env.storage().persistent().set(&DataKey::Config, &new_value);
    }

    pub fn get_config(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::Config)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Secure mirror
// ---------------------------------------------------------------------------

#[contract]
pub struct SecureConfigContract;

#[contractimpl]
impl SecureConfigContract {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// SECURE: retrieves the stored `Address` and calls `require_auth()`,
    /// which enforces a cryptographic signature check.
    pub fn set_config(env: Env, new_value: u32) {
        let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Config, &new_value);
    }

    pub fn get_config(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::Config)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env, String};

    // --- Vulnerable contract tests ---

    #[test]
    fn test_correct_string_passes_check() {
        let env = Env::default();
        let id = env.register_contract(None, ConfigContract);
        let client = ConfigContractClient::new(&env, &id);

        let admin_str = String::from_str(&env, "admin-secret");
        client.initialize(&admin_str);
        client.set_config(&admin_str, &42);

        assert_eq!(client.get_config(), 42);
    }

    /// Demonstrates the vulnerability: any caller who supplies the matching
    /// string value passes the check — no private key required.
    #[test]
    fn test_any_caller_with_matching_string_passes() {
        let env = Env::default();
        let id = env.register_contract(None, ConfigContract);
        let client = ConfigContractClient::new(&env, &id);

        let admin_str = String::from_str(&env, "admin-secret");
        client.initialize(&admin_str);

        // An attacker who knows the string can call set_config without any key.
        let attacker_str = String::from_str(&env, "admin-secret");
        client.set_config(&attacker_str, &99);

        assert_eq!(client.get_config(), 99);
    }

    // --- Secure contract tests ---

    #[test]
    fn test_secure_requires_address_auth() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SecureConfigContract);
        let client = SecureConfigContractClient::new(&env, &id);

        let admin = Address::generate(&env);
        client.initialize(&admin);
        client.set_config(&42);

        assert_eq!(client.get_config(), 42);
    }

    #[test]
    fn test_secure_rejects_without_auth() {
        let env = Env::default();
        // Deliberately do NOT mock auths — the call must fail.
        let id = env.register_contract(None, SecureConfigContract);
        let client = SecureConfigContractClient::new(&env, &id);

        let admin = Address::generate(&env);
        client.initialize(&admin);

        let result = client.try_set_config(&42);
        assert!(result.is_err());
    }
}
