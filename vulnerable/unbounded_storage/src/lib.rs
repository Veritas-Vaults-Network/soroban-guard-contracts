//! VULNERABLE: Unbounded Vec Growth (DoS Vector)
//!
//! VULNERABILITY: Unbounded `Vec` growth in persistent storage — no length cap.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, String, Vec, Env};

#[contracttype]
pub enum DataKey { List }

#[contract]
pub struct UnboundedStorage;

#[contractimpl]
impl UnboundedStorage {
    /// VULNERABLE: no length cap — unbounded growth.
    pub fn append(env: Env, item: String) {
        let key = DataKey::List;
        let mut list: Vec<String> = env.storage().persistent().get(&key).unwrap_or(Vec::new(&env));
        list.push_back(item); // ❌ no cap
        env.storage().persistent().set(&key, &list);
    }

    /// Returns all items currently in the list.
    pub fn list(env: Env) -> Vec<String> {
        env.storage().persistent().get(&DataKey::List).unwrap_or(Vec::new(&env))
    }

    /// Returns the number of items currently in the list.
    pub fn len(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get::<DataKey, Vec<String>>(&DataKey::List)
            .map(|v| v.len())
            .unwrap_or(0)
    }
}

pub mod secure {
    use soroban_sdk::{contract, contractimpl, String, Vec, Env};
    use super::DataKey;

    const MAX_HISTORY: u32 = 50;

    #[contract]
    pub struct BoundedStorage;

    #[contractimpl]
    impl BoundedStorage {
        /// SECURE: ring-buffer eviction at MAX_HISTORY.
        pub fn append(env: Env, item: String) {
            let key = DataKey::List;
            let mut list: Vec<String> = env.storage().persistent().get(&key).unwrap_or(Vec::new(&env));
            if list.len() >= MAX_HISTORY { list.remove(0); } // ✅
            list.push_back(item);
            env.storage().persistent().set(&key, &list);
        }

        pub fn list(env: Env) -> Vec<String> {
            env.storage().persistent().get(&DataKey::List).unwrap_or(Vec::new(&env))
        }

        pub fn len(env: Env) -> u32 {
            env.storage()
                .persistent()
                .get::<DataKey, Vec<String>>(&DataKey::List)
                .map(|v| v.len())
                .unwrap_or(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{Env, String};

    #[test]
    fn test_normal_append_works() {
        let env = Env::default();
        let id = env.register_contract(None, UnboundedStorage);
        let client = UnboundedStorageClient::new(&env, &id);
        client.append(&String::from_str(&env, "entry-1"));
        client.append(&String::from_str(&env, "entry-2"));
        assert_eq!(client.len(), 2);
    }

    #[test]
    fn test_large_number_of_appends_grows_unbounded() {
        let env = Env::default();
        env.budget().reset_unlimited();
        let id = env.register_contract(None, UnboundedStorage);
        let client = UnboundedStorageClient::new(&env, &id);
        for _ in 0..200u32 {
            client.append(&String::from_str(&env, "item"));
        }
        assert_eq!(client.len(), 200);
    }

    #[test]
    fn test_secure_enforces_max_history_cap() {
        let env = Env::default();
        env.budget().reset_unlimited();
        let id = env.register_contract(None, secure::BoundedStorage);
        let client = secure::BoundedStorageClient::new(&env, &id);
        for _ in 0..70u32 {
            client.append(&String::from_str(&env, "item"));
        }
        assert_eq!(client.len(), 50);
    }
}
