//! Secure version of the admin contract that emits events on admin changes.

use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

const ADMIN_KEY: &str = "admin";

#[contract]
pub struct SecureAdminContract;

#[contractimpl]
impl SecureAdminContract {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&ADMIN_KEY) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&ADMIN_KEY, &admin);
    }

    /// SECURE: emits an AdminChg event after updating the admin.
    pub fn set_admin(env: Env, new_admin: Address) {
        let old_admin: Address = env
            .storage()
            .persistent()
            .get(&ADMIN_KEY)
            .expect("not initialized");
        old_admin.require_auth();

        env.storage().persistent().set(&ADMIN_KEY, &new_admin);

        // ✅ Emit event so off-chain monitors can detect the change
        env.events()
            .publish((symbol_short!("AdminChg"),), (old_admin, new_admin));
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&ADMIN_KEY)
            .expect("not initialized")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Events},
        Address, Env, TryFromVal, Val, Vec,
    };

    fn setup() -> (Env, SecureAdminContractClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SecureAdminContract);
        let client = SecureAdminContractClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, client, admin)
    }

    #[test]
    fn test_secure_set_admin_emits_event() {
        let (env, client, old_admin) = setup();
        let new_admin = Address::generate(&env);

        client.set_admin(&new_admin);

        let events = env.events().all();
        assert_eq!(events.len(), 1, "expected exactly one AdminChg event");

        let (_, topics, data) = events.last().unwrap();

        // Verify topic is ("AdminChg",)
        let topic_vec = Vec::<Val>::try_from_val(&env, &topics).unwrap();
        let topic_sym =
            soroban_sdk::Symbol::try_from_val(&env, &topic_vec.get(0).unwrap()).unwrap();
        assert_eq!(topic_sym, symbol_short!("AdminChg"));

        // Verify data contains (old_admin, new_admin)
        let data_vec = Vec::<Val>::try_from_val(&env, &data).unwrap();
        let emitted_old = Address::try_from_val(&env, &data_vec.get(0).unwrap()).unwrap();
        let emitted_new = Address::try_from_val(&env, &data_vec.get(1).unwrap()).unwrap();
        assert_eq!(emitted_old, old_admin);
        assert_eq!(emitted_new, new_admin);
    }

    #[test]
    fn test_secure_set_admin_requires_current_admin_auth() {
        extern crate std;
        let (env, client, _admin) = setup();
        let attacker = Address::generate(&env);

        // Drop mocked auths — no auth provided for the next call.
        env.set_auths(&[]);

        // Call without any auth — should panic
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.set_admin(&attacker);
        }));

        assert!(
            result.is_err(),
            "set_admin must panic without current admin auth"
        );
    }

    #[test]
    fn test_secure_reinit_panics() {
        extern crate std;
        let (env, client, admin) = setup();

        // Drop mocked auths for the re-init attempt
        env.set_auths(&[]);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.initialize(&admin);
        }));

        assert!(
            result.is_err(),
            "initialize must panic on re-initialization"
        );
    }
}
