//! SECURE mirror: typed `#[contracttype]` enum keys prevent collisions.
//!
//! Each variant carries its own discriminant in the serialised key, so
//! `DataKey::Admin` and `DataKey::Balance(addr)` can never occupy the same
//! storage slot even if the inner values happen to be equal.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    Balance(Address),
}

#[contract]
pub struct SecureContract;

#[contractimpl]
impl SecureContract {
    pub fn set_admin(env: Env, admin: Address) {
        // ✅ Typed variant — namespace-isolated from all other keys.
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    pub fn get_admin(env: Env) -> Option<Address> {
        env.storage().persistent().get(&DataKey::Admin)
    }

    pub fn set_balance(env: Env, user: Address, amount: u64) {
        // ✅ Variant wraps the address — unique per user, never aliases Admin.
        env.storage()
            .persistent()
            .set(&DataKey::Balance(user), &amount);
    }

    pub fn get_balance(env: Env, user: Address) -> Option<u64> {
        env.storage().persistent().get(&DataKey::Balance(user))
    }
}
