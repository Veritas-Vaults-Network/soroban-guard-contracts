//! SECURE: Protected Fee Withdrawal
//!
//! Secure mirror of `unprotected_fee_withdraw`. The `withdraw_fees()` function
//! now requires the stored admin to authorize the call before any funds move.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    Fees,
}

#[contract]
pub struct ProtectedFeeWithdraw;

#[contractimpl]
impl ProtectedFeeWithdraw {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Fees, &0i128);
    }

    pub fn swap(env: Env, amount_in: i128, fee_rate: i128) {
        let fee = (amount_in * fee_rate) / 10000;
        let current: i128 = env.storage().persistent().get(&DataKey::Fees).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Fees, &(current + fee));
        env.events().publish((symbol_short!("swap"),), (amount_in, fee_rate, fee));
    }

    /// SECURE: Only the stored admin may withdraw accumulated fees.
    pub fn withdraw_fees(env: Env, recipient: Address) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        // ✅ Admin must authorize this call.
        admin.require_auth();

        let fees: i128 = env.storage().persistent().get(&DataKey::Fees).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Fees, &0i128);
        env.events().publish((symbol_short!("fee_out"),), (recipient, fees));
    }

    pub fn get_fees(env: Env) -> i128 {
        env.storage().persistent().get(&DataKey::Fees).unwrap_or(0)
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage().persistent().get(&DataKey::Admin).expect("not initialized")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, ProtectedFeeWithdrawClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, ProtectedFeeWithdraw);
        let client = ProtectedFeeWithdrawClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, admin, client)
    }

    #[test]
    fn test_admin_can_withdraw_fees() {
        let (_env, admin, client) = setup();
        client.swap(&1000, &25);
        client.swap(&2000, &25);
        assert_eq!(client.get_fees(), 7);
        client.withdraw_fees(&admin);
        assert_eq!(client.get_fees(), 0);
    }

    #[test]
    #[should_panic]
    fn test_non_admin_cannot_withdraw_fees() {
        let (env, _admin, client) = setup();
        let attacker = Address::generate(&env);
        client.swap(&1000, &25);
        // No auth for admin — should panic.
        client.withdraw_fees(&attacker);
    }
}
