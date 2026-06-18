pub mod secure {
    use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

    #[contracttype]
    pub enum DataKey {
        Admin,
        Balance(Address),
    }

    #[contract]
    pub struct SecureToken;

    #[contractimpl]
    impl SecureToken {
        /// Stores admin once; panics if already initialised.
        pub fn initialize(env: Env, admin: Address) {
            if env.storage().persistent().has(&DataKey::Admin) {
                panic!("already initialised");
            }
            env.storage().persistent().set(&DataKey::Admin, &admin);
        }

        /// Admin-gated mint.
        pub fn mint(env: Env, to: Address, amount: i128) {
            let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
            admin.require_auth();
            let key = DataKey::Balance(to);
            let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
            env.storage().persistent().set(&key, &(bal + amount));
        }

        /// ✅ `from` must authorise every transfer.
        pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
            from.require_auth();
            let from_key = DataKey::Balance(from.clone());
            let to_key = DataKey::Balance(to.clone());
            let from_bal: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
            let to_bal: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);
            env.storage()
                .persistent()
                .set(&from_key, &(from_bal - amount));
            env.storage().persistent().set(&to_key, &(to_bal + amount));
            env.events()
                .publish((symbol_short!("transfer"),), (from, to, amount));
        }

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
        use soroban_sdk::{testutils::Address as _, Address, Env};

        /// transfer without mock_all_auths must panic (host rejects missing auth).
        #[test]
        #[should_panic]
        fn test_secure_transfer_requires_from_auth() {
            let env = Env::default();
            let contract_id = env.register_contract(None, SecureToken);
            let client = SecureTokenClient::new(&env, &contract_id);
            let admin = Address::generate(&env);
            let alice = Address::generate(&env);
            let bob = Address::generate(&env);
            // initialize needs no auth; mint is called without auth check here to seed state
            env.mock_all_auths();
            client.initialize(&admin);
            client.mint(&alice, &500);
            // Clear all auth mocks — transfer must now panic
            env.set_auths(&[]);
            client.transfer(&alice, &bob, &500);
        }

        /// mint without admin auth mock must panic.
        #[test]
        #[should_panic]
        fn test_secure_mint_requires_admin_auth() {
            let env = Env::default();
            let contract_id = env.register_contract(None, SecureToken);
            let client = SecureTokenClient::new(&env, &contract_id);
            let admin = Address::generate(&env);
            env.mock_all_auths();
            client.initialize(&admin);
            // Clear all auth mocks — mint must now panic
            env.set_auths(&[]);
            let alice = Address::generate(&env);
            client.mint(&alice, &1000);
        }

        /// With correct auth mocks, balances update as expected.
        #[test]
        fn test_secure_normal_transfer_works() {
            let env = Env::default();
            let contract_id = env.register_contract(None, SecureToken);
            let client = SecureTokenClient::new(&env, &contract_id);
            let admin = Address::generate(&env);
            let alice = Address::generate(&env);
            let bob = Address::generate(&env);

            env.mock_all_auths();
            client.initialize(&admin);
            client.mint(&alice, &1000);
            client.transfer(&alice, &bob, &400);

            assert_eq!(client.balance(&alice), 600);
            assert_eq!(client.balance(&bob), 400);
        }
    }
}
