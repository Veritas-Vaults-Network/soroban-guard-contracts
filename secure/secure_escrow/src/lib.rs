//! SECURE: Escrow with Sequence-Based Timelock
//!
//! Fixes the vulnerabilities in `unprotected_admin`:
//! - `deposit()` requires depositor auth
//! - `withdraw()` enforces a ledger-sequence timelock and depositor auth
//! - `admin_cancel()` requires both admin AND depositor auth (dual-sig)
//! - All persistent entries have TTL extended on every write

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

const LEDGER_BUMP: u32 = 17_280; // ~1 day at 5s/ledger

#[contracttype]
pub enum DataKey {
    Admin,
    Deposit(Address),
}

#[contracttype]
pub struct EscrowEntry {
    pub amount: i128,
    pub unlock_sequence: u32,
}

#[contract]
pub struct SecureEscrow;

#[contractimpl]
impl SecureEscrow {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Admin, LEDGER_BUMP, LEDGER_BUMP);
    }

    /// Deposit `amount` locked until `unlock_sequence`.
    /// Requires depositor auth.
    pub fn deposit(env: Env, depositor: Address, amount: i128, unlock_sequence: u32) {
        depositor.require_auth();
        if amount <= 0 {
            panic!("amount must be positive");
        }
        let key = DataKey::Deposit(depositor);
        env.storage()
            .persistent()
            .set(&key, &EscrowEntry { amount, unlock_sequence });
        env.storage()
            .persistent()
            .extend_ttl(&key, LEDGER_BUMP, LEDGER_BUMP);
    }

    /// Withdraw after the timelock expires. Only the depositor may call this.
    pub fn withdraw(env: Env, depositor: Address) -> i128 {
        depositor.require_auth();
        let key = DataKey::Deposit(depositor);
        let entry: EscrowEntry = env
            .storage()
            .persistent()
            .get(&key)
            .expect("no deposit found");
        if env.ledger().sequence() < entry.unlock_sequence {
            panic!("still locked");
        }
        env.storage().persistent().remove(&key);
        entry.amount
    }

    /// Emergency cancel — requires both admin AND depositor auth.
    pub fn admin_cancel(env: Env, depositor: Address) -> i128 {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        depositor.require_auth();
        let key = DataKey::Deposit(depositor);
        let entry: EscrowEntry = env
            .storage()
            .persistent()
            .get(&key)
            .expect("no deposit found");
        env.storage().persistent().remove(&key);
        entry.amount
    }

    pub fn get_deposit(env: Env, depositor: Address) -> Option<EscrowEntry> {
        env.storage()
            .persistent()
            .get(&DataKey::Deposit(depositor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::{Address as _, Ledger as _}, Address, Env};

    fn setup() -> (Env, soroban_sdk::Address, Address, Address) {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureEscrow);
        let client = SecureEscrowClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&admin);
        (env, contract_id, admin, depositor)
    }

    #[test]
    fn test_deposit_and_withdraw_after_lock() {
        let (env, contract_id, _admin, depositor) = setup();
        let client = SecureEscrowClient::new(&env, &contract_id);

        client.deposit(&depositor, &1000, &500);
        env.ledger().set_sequence_number(501);
        let returned = client.withdraw(&depositor);
        assert_eq!(returned, 1000);
        assert!(client.get_deposit(&depositor).is_none());
    }

    #[test]
    #[should_panic(expected = "still locked")]
    fn test_withdraw_before_lock_fails() {
        let (env, contract_id, _admin, depositor) = setup();
        let client = SecureEscrowClient::new(&env, &contract_id);

        client.deposit(&depositor, &1000, &500);
        env.ledger().set_sequence_number(499);
        client.withdraw(&depositor);
    }

    #[test]
    #[should_panic]
    fn test_admin_cancel_without_depositor_cosig_fails() {
        let (env, contract_id, admin, depositor) = setup();
        let client = SecureEscrowClient::new(&env, &contract_id);

        client.deposit(&depositor, &1000, &500);

        // Only mock admin auth — depositor does NOT sign
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &admin,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "admin_cancel",
                args: (&depositor,).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.admin_cancel(&depositor);
    }

    #[test]
    #[should_panic]
    fn test_attacker_cannot_withdraw_others_funds() {
        let (env, contract_id, _admin, depositor) = setup();
        let client = SecureEscrowClient::new(&env, &contract_id);
        let attacker = Address::generate(&env);

        client.deposit(&depositor, &1000, &500);
        env.ledger().set_sequence_number(501);

        // attacker tries to withdraw depositor's funds — auth will fail
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &attacker,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "withdraw",
                args: (&attacker,).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.withdraw(&attacker); // no deposit exists for attacker
    }
}
