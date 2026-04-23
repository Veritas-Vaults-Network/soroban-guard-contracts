//! VULNERABLE: Reentrancy via external callbacks before state update.
//!
//! A vault that notifies an external contract before reducing the user's
//! balance. An attacker-controlled notifier can call back into `withdraw()`
//! while the original user's balance is still intact.
//!
//! VULNERABILITY: `withdraw()` performs an external call before updating
//! contract state, opening a reentrancy window.
//!
//! SECURE MIRROR: `secure::SecureReentrantVault` updates state before calling
//! the external contract, blocking the reentrant callback.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Withdrawn(Address),
}

#[contracttype]
pub enum NotifyDataKey {
    Vault,
    Notify,
    Reenter,
}

#[contract]
pub struct ReentrantVault;

#[contractimpl]
impl ReentrantVault {
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = DataKey::Balance(user.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&key, &(current + amount));
    }

    pub fn withdraw(env: Env, user: Address, amount: i128, notify_id: Address) {
        user.require_auth();

        let balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(user.clone()))
            .unwrap_or(0);

        // ❌ External call BEFORE state update — reentrancy window.
        NotifyContractClient::new(&env, &notify_id).on_withdraw(&user, &amount);

        let new_balance = balance.checked_sub(amount).expect("insufficient funds");
        env.storage()
            .persistent()
            .set(&DataKey::Balance(user.clone()), &new_balance);

        let withdrawn_key = DataKey::Withdrawn(user.clone());
        let withdrawn: i128 = env.storage().persistent().get(&withdrawn_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&withdrawn_key, &(withdrawn + amount));
    }

    pub fn get_balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }

    pub fn get_withdrawn(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Withdrawn(user))
            .unwrap_or(0)
    }
}

#[contract]
pub struct NotifyContract;

#[contractimpl]
impl NotifyContract {
    pub fn configure(env: Env, vault_id: Address, notify_id: Address, reenter: bool) {
        env.storage()
            .persistent()
            .set(&NotifyDataKey::Vault, &vault_id);
        env.storage()
            .persistent()
            .set(&NotifyDataKey::Notify, &notify_id);
        env.storage()
            .persistent()
            .set(&NotifyDataKey::Reenter, &reenter);
    }

    pub fn on_withdraw(env: Env, user: Address, amount: i128) {
        let reenter: bool = env
            .storage()
            .persistent()
            .get(&NotifyDataKey::Reenter)
            .unwrap_or(false);

        if reenter {
            env.storage()
                .persistent()
                .set(&NotifyDataKey::Reenter, &false);

            let vault_id: Address = env
                .storage()
                .persistent()
                .get(&NotifyDataKey::Vault)
                .expect("vault not configured");
            let notify_id: Address = env
                .storage()
                .persistent()
                .get(&NotifyDataKey::Notify)
                .expect("notify contract not configured");

            ReentrantVaultClient::new(&env, &vault_id).withdraw(&user, &amount, &notify_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (
        Env,
        Address,
        ReentrantVaultClient<'static>,
        Address,
        NotifyContractClient<'static>,
    ) {
        let env = Env::default();
        let vault_id = env.register_contract(None, ReentrantVault);
        let vault_client = ReentrantVaultClient::new(&env, &vault_id);
        let notify_id = env.register_contract(None, NotifyContract);
        let notify_client = NotifyContractClient::new(&env, &notify_id);
        (env, vault_id, vault_client, notify_id, notify_client)
    }

    #[test]
    fn test_normal_withdraw_works() {
        let (env, vault_id, vault_client, notify_id, notify_client) = setup();
        env.mock_all_auths();

        let alice = Address::generate(&env);
        vault_client.deposit(&alice, &1000);
        notify_client.configure(&vault_id, &notify_id, &false);

        vault_client.withdraw(&alice, &400, &notify_id);

        assert_eq!(vault_client.get_balance(&alice), 600);
        assert_eq!(vault_client.get_withdrawn(&alice), 400);
    }

    #[test]
    fn test_reentrant_withdraw_drains_more_than_balance() {
        let (env, vault_id, vault_client, notify_id, notify_client) = setup();
        env.mock_all_auths();

        let alice = Address::generate(&env);
        vault_client.deposit(&alice, &1000);
        notify_client.configure(&vault_id, &notify_id, &true);

        vault_client.withdraw(&alice, &1000, &notify_id);

        assert_eq!(vault_client.get_balance(&alice), 0);
        assert_eq!(vault_client.get_withdrawn(&alice), 2000);
    }

    #[test]
    fn test_secure_reentrant_withdraw_blocks_the_attack() {
        use crate::secure::SecureReentrantVaultClient;

        let env = Env::default();
        let vault_id = env.register_contract(None, secure::SecureReentrantVault);
        let vault_client = SecureReentrantVaultClient::new(&env, &vault_id);
        let notify_id = env.register_contract(None, NotifyContract);
        let notify_client = NotifyContractClient::new(&env, &notify_id);

        env.mock_all_auths();

        let alice = Address::generate(&env);
        vault_client.deposit(&alice, &1000);
        notify_client.configure(&vault_id, &notify_id, &true);

        let result = std::panic::catch_unwind(|| {
            vault_client.withdraw(&alice, &1000, &notify_id);
        });

        assert!(result.is_err());
        assert_eq!(vault_client.get_balance(&alice), 1000);
        assert_eq!(vault_client.get_withdrawn(&alice), 0);
    }
}
