//! Secure version: stores only a hash commitment, never the raw secret.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, Env};

#[contract]
pub struct SecureStorageContract;

#[contracttype]
enum DataKey {
    Admin,
    Commitment,
}

#[contractimpl]
impl SecureStorageContract {
    /// SECURE: stores only a hash commitment — the raw secret never touches the ledger.
    pub fn initialize(env: Env, admin: Address, secret_hash: Bytes) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
        // ✅ Only the hash is stored — the raw secret never touches the ledger
        env.storage()
            .persistent()
            .set(&DataKey::Commitment, &secret_hash);
    }

    /// Returns the stored hash commitment.
    pub fn get_commitment(env: Env) -> Bytes {
        env.storage()
            .persistent()
            .get(&DataKey::Commitment)
            .expect("commitment not set")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Bytes, Env};

    #[test]
    fn test_secure_stores_hash_not_secret() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SecureStorageContract);
        let client = SecureStorageContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        // Simulate a SHA-256 hash (32 bytes) — raw secret never sent on-chain
        let hash = Bytes::from_slice(&env, &[0xab_u8; 32]);

        client.initialize(&admin, &hash);

        let stored_commitment = client.get_commitment();
        assert_eq!(stored_commitment, hash);
        // Note: get_secret method does not exist on SecureStorageContractClient
        // because we never defined it — raw secret is never exposed
    }

    #[test]
    fn test_secure_initialize_requires_admin_auth() {
        extern crate std;
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SecureStorageContract);
        let client = SecureStorageContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let hash = Bytes::from_slice(&env, &[0xcd_u8; 32]);

        // Drop mocked auths — no auth provided for initialize
        env.set_auths(&[]);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.initialize(&admin, &hash);
        }));

        assert!(result.is_err(), "initialize must panic without admin auth");
    }

    #[test]
    fn test_secure_commitment_is_deterministic() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SecureStorageContract);
        let client = SecureStorageContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let hash = Bytes::from_slice(&env, &[0xef_u8; 32]);

        client.initialize(&admin, &hash);

        let stored_commitment = client.get_commitment();
        assert_eq!(stored_commitment, hash);

        // Second initialization attempt should panic due to re-init guard
        extern crate std;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.initialize(&admin, &hash);
        }));

        assert!(
            result.is_err(),
            "initialize must panic on re-initialization"
        );
    }
}
