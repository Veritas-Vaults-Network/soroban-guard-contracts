//! VULNERABLE: Sensitive data stored in persistent storage.
//!
//! A contract that stores a raw secret key in Soroban persistent storage.
//! All ledger state is public on Stellar — any observer can read the value
//! directly from ledger state without invoking the contract.
//!
//! VULNERABILITY: `initialize()` writes raw secret material to persistent
//! storage, exposing it to anyone who can read the ledger.
//!
//! SECURE MIRROR: see `secure.rs` — stores only a SHA-256 hash commitment
//! on-chain; raw secret never touched by the contract.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, Env};

mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
    SecretKey,
}

#[contract]
pub struct SensitiveStorageContract;

#[contractimpl]
impl SensitiveStorageContract {
    /// VULNERABLE: stores the raw `secret_key` in persistent storage.
    /// All Stellar ledger state is public — any observer can read this value directly.
    ///
    /// # Vulnerability
    /// Raw secret written to public ledger. Impact: secret is readable by anyone without auth.
    pub fn initialize(env: Env, admin: Address, secret_key: Bytes) {
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
        // ❌ Raw secret written to public ledger state — readable by anyone
        env.storage()
            .persistent()
            .set(&DataKey::SecretKey, &secret_key);
    }

    /// Returns the raw secret from storage. No auth required — the ledger is already public.
    pub fn get_secret(env: Env) -> Bytes {
        env.storage()
            .persistent()
            .get(&DataKey::SecretKey)
            .expect("secret key not set")
    }

    /// Returns the stored admin address.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("admin not initialized")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Bytes, Env};

    #[test]
    fn test_secret_readable_after_initialize() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SensitiveStorageContract);
        let client = SensitiveStorageContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let secret = Bytes::from_slice(&env, b"super-secret-api-key-12345");

        client.initialize(&admin, &secret);

        // Secret is readable by anyone — no auth needed
        let stored = client.get_secret();
        assert_eq!(stored, secret);
    }

    #[test]
    fn test_any_address_can_read_secret() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SensitiveStorageContract);
        let client = SensitiveStorageContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let _attacker = Address::generate(&env);
        let secret = Bytes::from_slice(&env, b"private-key-material");

        client.initialize(&admin, &secret);

        // No auth mock needed — get_secret has no access control
        let stolen = client.get_secret();
        assert_eq!(stolen, secret);
    }
}
