//! VULNERABLE: Unprotected Fee Withdrawal
//!
//! A DEX-style contract that accumulates fees from swaps and exposes an
//! unguarded `withdraw_fees()` function. Any account can drain the contract's
//! accumulated fee balance to an arbitrary address.
//!
//! VULNERABILITY: `withdraw_fees()` mutates storage and transfers funds without
//! calling `admin.require_auth()`, allowing anyone to steal accumulated fees.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    Fees,
}

#[contract]
pub struct UnprotectedFeeWithdraw;

#[contractimpl]
impl UnprotectedFeeWithdraw {
    /// Initialise the contract with an admin and zero fee balance. Guards against re-init.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Fees, &0i128);
    }

    /// Simulate a swap that accumulates a fee proportional to `fee_rate` basis points.
    pub fn swap(env: Env, amount_in: i128, fee_rate: i128) {
        // In a real DEX, this would validate the swap and transfer tokens.
        // For this example, we just accumulate fees.
        let fee = (amount_in * fee_rate) / 10000;
        let current_fees: i128 = env.storage().persistent().get(&DataKey::Fees).unwrap_or(0);
        let new_fees = current_fees + fee;
        env.storage().persistent().set(&DataKey::Fees, &new_fees);

        env.events()
            .publish((symbol_short!("swap"),), (amount_in, fee_rate, fee));
    }

    /// VULNERABLE: Withdraws accumulated fees to an arbitrary recipient without
    /// verifying that the caller is the admin. Any account can call this and
    /// drain the contract's fee balance.
    pub fn withdraw_fees(env: Env, recipient: Address) {
        // ❌ Missing: let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        //             admin.require_auth();

        let fees: i128 = env.storage().persistent().get(&DataKey::Fees).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Fees, &0i128);

        // In a real contract, this would transfer tokens to the recipient.
        // For this example, we just emit an event to demonstrate the vulnerability.
        env.events()
            .publish((symbol_short!("withdraw_fees"),), (recipient.clone(), fees));
    }

    /// Returns the accumulated fee balance, defaulting to 0.
    pub fn get_fees(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Fees)
            .unwrap_or(0)
    }

    /// Returns the stored admin address. Panics if not initialized.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn test_admin_withdraws_fees_normally() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::random(&env);
        let contract = UnprotectedFeeWithdraw;

        contract.initialize(env.clone(), admin.clone());
        contract.swap(env.clone(), 1000, 25); // 0.25% fee = 2.5 (truncated to 2)
        contract.swap(env.clone(), 2000, 25); // 0.25% fee = 5

        assert_eq!(contract.get_fees(env.clone()), 7);

        contract.withdraw_fees(env.clone(), admin.clone());
        assert_eq!(contract.get_fees(env.clone()), 0);
    }

    #[test]
    fn test_attacker_withdraws_fees_without_auth() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::random(&env);
        let attacker = Address::random(&env);
        let contract = UnprotectedFeeWithdraw;

        contract.initialize(env.clone(), admin.clone());
        contract.swap(env.clone(), 1000, 25); // 0.25% fee = 2.5 (truncated to 2)
        contract.swap(env.clone(), 2000, 25); // 0.25% fee = 5

        assert_eq!(contract.get_fees(env.clone()), 7);

        // ❌ VULNERABILITY: Attacker can withdraw fees without being the admin.
        // This should panic in a secure implementation, but succeeds here.
        contract.withdraw_fees(env.clone(), attacker.clone());
        assert_eq!(contract.get_fees(env.clone()), 0);
    }

    #[test]
    fn test_fee_balance_zeroed_after_withdrawal() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::random(&env);
        let contract = UnprotectedFeeWithdraw;

        contract.initialize(env.clone(), admin.clone());
        contract.swap(env.clone(), 5000, 50); // 0.5% fee = 25

        assert_eq!(contract.get_fees(env.clone()), 25);

        contract.withdraw_fees(env.clone(), admin.clone());
        assert_eq!(contract.get_fees(env.clone()), 0);
    }
}
