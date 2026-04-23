//! SECURE mirror: enforces a minimum deposit threshold to prevent dust griefing.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

const MIN_DEPOSIT: i128 = 10_000;

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

#[contract]
pub struct SecureVault;

#[contractimpl]
impl SecureVault {
    /// ✅ Rejects deposits below MIN_DEPOSIT, preventing storage bloat attacks.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        assert!(amount >= MIN_DEPOSIT, "below minimum deposit");
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
