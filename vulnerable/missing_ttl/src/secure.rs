//! SECURE mirror: refresh persistent-entry TTL after every balance read/write.
//!
//! This keeps active accounts alive by renewing their balance slots whenever
//! they are accessed. The example focuses on persistent data entries; in a
//! production contract you should also maintain contract instance/code TTL.

use crate::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env};

fn extend_balance_ttl(env: &Env, key: &DataKey) {
    let max_ttl = env.storage().max_ttl();
    let threshold = max_ttl.saturating_sub(1);
    env.storage()
        .persistent()
        .extend_ttl(key, threshold, max_ttl);
}

fn get_balance(env: &Env, account: &Address) -> i128 {
    let key = DataKey::Balance(account.clone());
    let balance: Option<i128> = env.storage().persistent().get(&key);

    if balance.is_some() {
        // ✅ Renew TTL after every successful read.
        extend_balance_ttl(env, &key);
    }

    balance.unwrap_or(0)
}

fn set_balance(env: &Env, account: &Address, amount: i128) {
    let key = DataKey::Balance(account.clone());
    env.storage().persistent().set(&key, &amount);
    // ✅ Renew TTL after every write.
    extend_balance_ttl(env, &key);
}

#[contract]
pub struct SecureToken;

#[contractimpl]
impl SecureToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let current = get_balance(&env, &to);
        let new_balance = current.checked_add(amount).expect("mint: balance overflow");
        set_balance(&env, &to, new_balance);
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        get_balance(&env, &account)
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();

        let from_balance = get_balance(&env, &from);
        let to_balance = get_balance(&env, &to);

        let new_from = from_balance
            .checked_sub(amount)
            .expect("transfer: insufficient balance");
        let new_to = to_balance
            .checked_add(amount)
            .expect("transfer: recipient balance overflow");

        set_balance(&env, &from, new_from);
        set_balance(&env, &to, new_to);
    }
}
