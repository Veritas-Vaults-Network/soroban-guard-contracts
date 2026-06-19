//! SECURE: Token contract with proper event emission
//!
//! This is the secure version of the missing_events vulnerability.
//! Every state-mutating operation (mint, burn, transfer) emits an event
//! so that off-chain indexers can track all supply and balance changes.

use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

#[contract]
pub struct SecureToken;

#[contractimpl]
impl SecureToken {
    /// Mint tokens to an address.
    ///
    /// # Fix
    /// Emits a "mint" event after the balance is updated, so off-chain
    /// indexers can track the supply change.
    pub fn mint(env: Env, to: Address, amount: i128) {
        let key = DataKey::Balance(to.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));

        // ✅ Emit mint event so off-chain indexers can track supply changes
        env.events().publish((symbol_short!("mint"),), (to, amount));
    }

    /// Burn tokens from an address.
    ///
    /// # Fix
    /// Emits a "burn" event after the balance is updated, so off-chain
    /// indexers can track the supply change.
    pub fn burn(env: Env, from: Address, amount: i128) {
        let key = DataKey::Balance(from.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current - amount));

        // ✅ Emit burn event so off-chain indexers can track supply changes
        env.events()
            .publish((symbol_short!("burn"),), (from, amount));
    }

    /// Transfer tokens between addresses.
    ///
    /// This function already emits a transfer event in the vulnerable version.
    /// The fix to transfer is not needed — it is kept unchanged as a baseline.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        let from_key = DataKey::Balance(from.clone());
        let to_key = DataKey::Balance(to.clone());

        let from_balance: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
        let to_balance: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);

        env.storage()
            .persistent()
            .set(&from_key, &(from_balance - amount));
        env.storage()
            .persistent()
            .set(&to_key, &(to_balance + amount));

        env.events()
            .publish((symbol_short!("transfer"),), (from, to, amount));
    }

    /// Returns the balance of `account`, defaulting to 0.
    pub fn balance(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Events},
        Address, Env, Symbol, TryFromVal, Val, Vec,
    };

    #[test]
    fn test_secure_mint_emits_event() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureToken);
        let client = SecureTokenClient::new(&env, &contract_id);

        let alice = Address::generate(&env);

        // Mint tokens
        client.mint(&alice, &500);

        // Verify the balance was updated
        assert_eq!(client.balance(&alice), 500);

        // Check that exactly one event was published with the "mint" topic
        let events = env.events().all();
        assert_eq!(events.len(), 1, "Expected exactly one event");

        let (_, topics, data) = events.get(0).unwrap();
        assert_eq!(topics.len(), 1, "Expected exactly one topic");

        // Verify the topic is "mint" by extracting the symbol
        let topic0: Val = topics.get(0).unwrap().clone();
        let topic_symbol = Symbol::try_from_val(&env, &topic0).expect("topic should be a symbol");
        assert_eq!(topic_symbol, symbol_short!("mint"));

        // Verify the data contains (alice, 500)
        let data_tuple: Vec<Val> =
            Vec::<Val>::try_from_val(&env, &data).expect("data should be a tuple");
        assert_eq!(data_tuple.len(), 2, "event data should have 2 fields");

        let event_to: Address =
            Address::try_from_val(&env, &data_tuple.get(0).unwrap()).expect("first field is to");
        let event_amount: i128 =
            i128::try_from_val(&env, &data_tuple.get(1).unwrap()).expect("second field is amount");

        assert_eq!(event_to, alice);
        assert_eq!(event_amount, 500);
    }

    #[test]
    fn test_secure_burn_emits_event() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureToken);
        let client = SecureTokenClient::new(&env, &contract_id);

        let alice = Address::generate(&env);

        // Mint some tokens first
        client.mint(&alice, &1000);

        // Burn tokens (this will emit the burn event)
        client.burn(&alice, &300);

        // Verify the balance was updated
        assert_eq!(client.balance(&alice), 700);

        // Check that exactly one event was published with the "burn" topic
        // (The mint event came first, then the burn event)
        let events = env.events().all();
        assert_eq!(events.len(), 2, "Expected mint and burn events");

        let (_, topics, data) = events.get(1).unwrap(); // Get the second event (burn)
        assert_eq!(topics.len(), 1, "Expected exactly one topic");

        // Verify the topic is "burn" by extracting the symbol
        let topic0: Val = topics.get(0).unwrap().clone();
        let topic_symbol = Symbol::try_from_val(&env, &topic0).expect("topic should be a symbol");
        assert_eq!(topic_symbol, symbol_short!("burn"));

        // Verify the data contains (alice, 300)
        let data_tuple: Vec<Val> =
            Vec::<Val>::try_from_val(&env, &data).expect("data should be a tuple");
        assert_eq!(data_tuple.len(), 2, "event data should have 2 fields");

        let event_from: Address =
            Address::try_from_val(&env, &data_tuple.get(0).unwrap()).expect("first field is from");
        let event_amount: i128 =
            i128::try_from_val(&env, &data_tuple.get(1).unwrap()).expect("second field is amount");

        assert_eq!(event_from, alice);
        assert_eq!(event_amount, 300);
    }

    #[test]
    fn test_secure_transfer_still_emits_event() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureToken);
        let client = SecureTokenClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        // Mint tokens to alice
        client.mint(&alice, &1000);

        // Transfer from alice to bob
        client.transfer(&alice, &bob, &300);

        // Verify balances
        assert_eq!(client.balance(&alice), 700);
        assert_eq!(client.balance(&bob), 300);

        // Check that events include transfer
        // (The mint event comes first, then the transfer event)
        let events = env.events().all();
        assert_eq!(events.len(), 2, "Expected mint and transfer events");

        let (_, topics, data) = events.get(1).unwrap(); // Get the second event (transfer)
        assert_eq!(topics.len(), 1, "Expected exactly one topic");

        // Verify the topic is "transfer" by extracting the symbol
        let topic0: Val = topics.get(0).unwrap().clone();
        let topic_symbol = Symbol::try_from_val(&env, &topic0).expect("topic should be a symbol");
        assert_eq!(topic_symbol, symbol_short!("transfer"));

        // Verify the data contains (alice, bob, 300)
        let data_tuple: Vec<Val> =
            Vec::<Val>::try_from_val(&env, &data).expect("data should be a tuple");
        assert_eq!(data_tuple.len(), 3, "event data should have 3 fields");

        let event_from: Address =
            Address::try_from_val(&env, &data_tuple.get(0).unwrap()).expect("first field is from");
        let event_to: Address =
            Address::try_from_val(&env, &data_tuple.get(1).unwrap()).expect("second field is to");
        let event_amount: i128 =
            i128::try_from_val(&env, &data_tuple.get(2).unwrap()).expect("third field is amount");

        assert_eq!(event_from, alice);
        assert_eq!(event_to, bob);
        assert_eq!(event_amount, 300);
    }
}
