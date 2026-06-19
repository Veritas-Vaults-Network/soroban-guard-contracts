//! SECURE: Self-Transfer Storage-Slot Collision fixed.
//!
//! The only change from the vulnerable contract is a single guard at the top of
//! `transfer`: when `from == to`, both balance keys resolve to the same storage
//! slot and the credit write overwrites the debit write, inflating the sender's
//! balance. Returning early (a no-op self-transfer) prevents the double-write
//! entirely. The `from.require_auth()` check is preserved unchanged.

use super::{get_balance, set_balance};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureToken;

#[contractimpl]
impl SecureToken {
    /// Mint `amount` tokens to `to`. No auth check — unprotected by design for test setup.
    pub fn mint(env: Env, to: Address, amount: i128) {
        let current = get_balance(&env, &to);
        set_balance(
            &env,
            &to,
            current.checked_add(amount).expect("mint overflow"),
        );
    }

    /// Returns the current balance of `account`, defaulting to 0.
    pub fn balance(env: Env, account: Address) -> i128 {
        get_balance(&env, &account)
    }

    /// SECURE: transfers `amount` from `from` to `to`.
    ///
    /// Treats a self-transfer as a no-op so the debit and credit writes can never
    /// collide on the same storage slot.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();

        // ✅ FIX: guard against self-transfer before any storage reads. When
        // `from == to` both balance keys map to the same slot, so the credit
        // write would overwrite the debit write and inflate the balance.
        // Returning early makes a self-transfer a no-op (the common token
        // standard behaviour), leaving the balance unchanged.
        if from == to {
            return;
        }

        let from_balance = get_balance(&env, &from);
        let to_balance = get_balance(&env, &to);
        set_balance(
            &env,
            &from,
            from_balance
                .checked_sub(amount)
                .expect("transfer underflow"),
        );
        set_balance(
            &env,
            &to,
            to_balance.checked_add(amount).expect("transfer overflow"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    /// Self-transfer is a no-op: alice's balance is unchanged, not inflated.
    #[test]
    fn test_secure_self_transfer_is_no_op() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureToken);
        let client = SecureTokenClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        env.mock_all_auths();

        client.mint(&alice, &1000);
        client.transfer(&alice, &alice, &500);

        // Balance is still 1000, not 1500 (the vulnerable inflation result).
        assert_eq!(client.balance(&alice), 1000);
    }

    #[test]
    fn test_secure_normal_transfer_works() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureToken);
        let client = SecureTokenClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        env.mock_all_auths();

        client.mint(&alice, &500);
        client.mint(&bob, &100);

        client.transfer(&alice, &bob, &200);

        assert_eq!(client.balance(&alice), 300);
        assert_eq!(client.balance(&bob), 300);
    }

    #[test]
    #[should_panic]
    fn test_secure_transfer_requires_from_auth() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureToken);
        let client = SecureTokenClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.mint(&alice, &500);
        // No mock_all_auths — should panic on require_auth.
        client.transfer(&alice, &bob, &100);
    }
}
