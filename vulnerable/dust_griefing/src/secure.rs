use soroban_sdk::{contract, contractimpl, Address, Env};
use super::{DataKey, MIN_DEPOSIT, get_balance, set_balance};

#[contract]
pub struct SecureVault;

#[contractimpl]
impl SecureVault {
    /// SECURE: rejects deposits below MIN_DEPOSIT.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        assert!(amount >= MIN_DEPOSIT, "below minimum deposit"); // ✅
        let bal = get_balance(&env, &user);
        set_balance(&env, &user, bal + amount);
    }

    pub fn balance(env: Env, user: Address) -> i128 {
        get_balance(&env, &user)
    }
}
