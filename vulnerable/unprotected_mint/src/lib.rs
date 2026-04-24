//! VULNERABLE: Unprotected Mint Function
//!
//! A token contract where `mint()` creates tokens for any address without
//! requiring admin authorization. Any caller can inflate the token supply
//! arbitrarily, minting unlimited tokens to any address.
//!
//! VULNERABILITY: Missing admin `require_auth()` before minting tokens.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    Balance(Address),
}

#[contract]
pub struct UnprotectedMintToken;

#[contractimpl]
impl UnprotectedMintToken {
    /// Store `admin` as the authorized minter. Must be called once before `mint`.
    pub fn initialize(env: Env, admin: Address) {
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// VULNERABLE: no admin.require_auth() — anyone can mint.
    pub fn mint(env: Env, to: Address, amount: i128) {
        let key = DataKey::Balance(to.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
        env.events().publish((symbol_short!("mint"),), (to, amount));
    }

    /// Returns the current token balance of `account`, defaulting to `0`.
    pub fn balance(env: Env, account: Address) -> i128 {
        env.storage().persistent().get(&DataKey::Balance(account)).unwrap_or(0)
    }
}

pub mod secure {
    use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};
    use super::DataKey;

    #[contract]
    pub struct SecureMintToken;

    #[contractimpl]
    impl SecureMintToken {
        pub fn initialize(env: Env, admin: Address) {
            env.storage().persistent().set(&DataKey::Admin, &admin);
        }

        /// SECURE: only the stored admin can mint.
        pub fn mint(env: Env, to: Address, amount: i128) {
            let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
            admin.require_auth(); // ✅
            let key = DataKey::Balance(to.clone());
            let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
            env.storage().persistent().set(&key, &(current + amount));
            env.events().publish((symbol_short!("mint"),), (to, amount));
        }

        pub fn balance(env: Env, account: Address) -> i128 {
            env.storage().persistent().get(&DataKey::Balance(account)).unwrap_or(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup_vulnerable() -> (Env, Address, Address, Address) {
        let env = Env::default();
        let contract_id = env.register_contract(None, UnprotectedMintToken);
        let admin = Address::generate(&env);
        let attacker = Address::generate(&env);
        UnprotectedMintTokenClient::new(&env, &contract_id).initialize(&admin);
        (env, contract_id, admin, attacker)
    }

    #[test]
    fn test_admin_mints_tokens_normally() {
        let (env, contract_id, admin, _) = setup_vulnerable();
        let client = UnprotectedMintTokenClient::new(&env, &contract_id);
        client.mint(&admin, &1_000);
        assert_eq!(client.balance(&admin), 1_000);
    }

    #[test]
    fn test_attacker_mints_without_auth() {
        let (env, contract_id, _admin, attacker) = setup_vulnerable();
        let client = UnprotectedMintTokenClient::new(&env, &contract_id);
        client.mint(&attacker, &999_999);
        assert_eq!(client.balance(&attacker), 999_999);
    }

    #[test]
    fn test_secure_admin_can_mint() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, secure::SecureMintToken);
        let admin = Address::generate(&env);
        let client = secure::SecureMintTokenClient::new(&env, &contract_id);
        client.initialize(&admin);
        client.mint(&admin, &500);
        assert_eq!(client.balance(&admin), 500);
    }

    #[test]
    #[should_panic]
    fn test_secure_attacker_cannot_mint() {
        let env = Env::default();
        let contract_id = env.register_contract(None, secure::SecureMintToken);
        let admin = Address::generate(&env);
        let attacker = Address::generate(&env);
        let client = secure::SecureMintTokenClient::new(&env, &contract_id);
        client.initialize(&admin);
        client.mint(&attacker, &999_999);
    }
}
