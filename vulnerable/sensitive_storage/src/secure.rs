//! SECURE: stores only a hash commitment, never raw secret material.
//!
//! All Soroban ledger state is public, so API keys, private keys, seeds, and
//! other raw secrets must stay off-chain. This mirror stores only a public
//! commitment that callers can compare against off-chain secret material.

use super::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Bytes, Env};

#[contract]
pub struct SecureStorageContract;

#[contractimpl]
impl SecureStorageContract {
    /// SECURE: stores only a hash commitment; raw secrets never touch storage.
    pub fn initialize(env: Env, admin: Address, secret_hash: Bytes) {
        if env.storage().persistent().has(&DataKey::Commitment) {
            panic!("already initialized");
        }

        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
        // ✅ Only the hash commitment is stored on-chain.
        env.storage()
            .persistent()
            .set(&DataKey::Commitment, &secret_hash);
    }

    /// Returns the stored public hash commitment.
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
        let hash = Bytes::from_slice(&env, &[0xab_u8; 32]);

        client.initialize(&admin, &hash);

        assert_eq!(client.get_commitment(), hash);
        let has_secret_key = env.as_contract(&contract_id, || {
            env.storage().persistent().has(&DataKey::SecretKey)
        });
        assert!(!has_secret_key);
        // SecureStorageContractClient has no get_secret method because the
        // secure contract never exposes raw secret material.
    }

    #[test]
    #[should_panic]
    fn test_secure_initialize_requires_admin_auth() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureStorageContract);
        let client = SecureStorageContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let hash = Bytes::from_slice(&env, &[0xcd_u8; 32]);

        client.initialize(&admin, &hash);
    }

    #[test]
    #[should_panic(expected = "already initialized")]
    fn test_secure_commitment_is_deterministic() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SecureStorageContract);
        let client = SecureStorageContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let hash = Bytes::from_slice(&env, &[0xef_u8; 32]);

        client.initialize(&admin, &hash);
        assert_eq!(client.get_commitment(), hash);

        // Re-initialization is blocked, so the stored commitment cannot be
        // overwritten after the first deterministic write.
        client.initialize(&admin, &hash);
    }
}
