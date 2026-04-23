//! VULNERABLE: Instant Oracle — Same-Ledger Price Manipulation
//!
//! An oracle where `set_price` and `get_price` can be called within the same
//! ledger (same transaction batch). This enables flash-loan-style attacks:
//! borrow funds → manipulate price → exploit a dependent contract → repay.
//!
//! VULNERABILITY: No delay is enforced between a price update and its
//! consumption. The stored price is immediately readable in the same ledger
//! it was written, so an attacker can atomically set an arbitrary price and
//! exploit any contract that trusts this oracle.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Price,
    UpdatedAt,
    Admin,
}

#[contract]
pub struct InstantOracle;

#[contractimpl]
impl InstantOracle {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// Update the price. No delay — readable immediately in the same ledger.
    /// VULNERABLE: ❌ Missing minimum-ledger-delay before price is consumable.
    pub fn set_price(env: Env, caller: Address, price: i128) {
        caller.require_auth();
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        if caller != admin {
            panic!("not admin");
        }
        env.storage().instance().set(&DataKey::Price, &price);
        env.storage()
            .instance()
            .set(&DataKey::UpdatedAt, &env.ledger().sequence());
    }

    /// Return the current price — no staleness or delay check.
    /// VULNERABLE: ❌ Price set in the same ledger is returned without restriction.
    pub fn get_price(env: Env) -> i128 {
        env.storage().instance().get(&DataKey::Price).unwrap_or(0)
    }

    pub fn updated_at(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::UpdatedAt)
            .unwrap_or(0)
    }
}

/// A dependent contract that uses the oracle price to compute a payout.
/// In a real attack the attacker would call set_price then consume_price
/// atomically within the same transaction / ledger.
#[contract]
pub struct DependentContract;

#[contractimpl]
impl DependentContract {
    /// Compute payout = amount * oracle_price.
    /// VULNERABLE: trusts whatever the oracle returns with no delay guard.
    pub fn compute_payout(env: Env, oracle_id: Address, amount: i128) -> i128 {
        let client = InstantOracleClient::new(&env, &oracle_id);
        let price = client.get_price();
        amount * price
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::{Address as _, Ledger as _}, Address, Env};

    fn setup() -> (Env, Address, InstantOracleClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, InstantOracle);
        let client = InstantOracleClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, admin, client)
    }

    /// Demonstrates the vulnerability: price set and read in the same ledger.
    #[test]
    fn test_price_set_and_read_same_ledger() {
        let (env, admin, client) = setup();

        env.ledger().set_sequence_number(100);

        // Set price at ledger 100
        client.set_price(&admin, &500);

        // ❌ VULNERABLE: price is immediately readable in the same ledger
        assert_eq!(client.get_price(), 500);
        assert_eq!(client.updated_at(), 100);
    }

    /// Demonstrates a dependent contract using a manipulated price in the same ledger.
    #[test]
    fn test_dependent_contract_uses_manipulated_price() {
        let env = Env::default();
        env.mock_all_auths();

        let oracle_id = env.register_contract(None, InstantOracle);
        let oracle = InstantOracleClient::new(&env, &oracle_id);
        let admin = Address::generate(&env);
        oracle.initialize(&admin);

        let dep_id = env.register_contract(None, DependentContract);
        let dep = DependentContractClient::new(&env, &dep_id);

        env.ledger().set_sequence_number(50);

        // Attacker sets an inflated price in the same ledger
        oracle.set_price(&admin, &1000);

        // ❌ VULNERABLE: dependent contract immediately sees the manipulated price
        let payout = dep.compute_payout(&oracle_id, &10);
        assert_eq!(payout, 10_000); // 10 * 1000 — exploited
    }
}
