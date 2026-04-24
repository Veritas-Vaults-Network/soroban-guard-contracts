//! VULNERABLE: Missing Zero-Address Check on Initialize
//!
//! A contract where `initialize(admin)` stores the admin without validating
//! that it is a real, non-default address. Passing the zero/default address
//! permanently bricks all admin-gated functions.
//!
//! VULNERABILITY: `initialize` never asserts that `admin` is a valid non-zero
//! address, so a caller can pass the Stellar zero address and lock the contract
//! forever — no one can ever satisfy `require_auth` for that address.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    Value,
}

#[contract]
pub struct ZeroAdminContract;

#[contractimpl]
impl ZeroAdminContract {
    /// VULNERABLE: accepts any address, including the zero/default address.
    /// Storing the zero address as admin permanently bricks all admin-gated functions.
    ///
    /// # Vulnerability
    /// Missing zero-address validation. Impact: contract permanently bricked if zero address stored.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        // ❌ Missing: assert admin != zero/default address
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// Admin-gated function — permanently inaccessible if admin is zero.
    /// Requires the stored admin to sign; if admin is the zero address no signer can satisfy this.
    pub fn set_value(env: Env, value: i128) {
        let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Value, &value);
    }

    /// Returns the stored config value, defaulting to 0.
    pub fn get_value(env: Env) -> i128 {
        env.storage().persistent().get(&DataKey::Value).unwrap_or(0)
    }

    /// Returns the stored admin address. Panics if not yet initialized.
    pub fn get_admin(env: Env) -> Address {
        env.storage().persistent().get(&DataKey::Admin).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env, String};

    // Stellar's "zero" account — all-zero public key, encodes to this strkey.
    const ZERO_ADDR: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

    fn setup() -> (Env, ZeroAdminContractClient<'static>) {
        let env = Env::default();
        let id = env.register_contract(None, ZeroAdminContract);
        let client = ZeroAdminContractClient::new(&env, &id);
        (env, client)
    }

    /// A valid admin address initializes correctly.
    #[test]
    fn test_valid_admin_initializes() {
        let (env, client) = setup();
        let admin = Address::generate(&env);
        client.initialize(&admin);
        assert_eq!(client.get_admin(), admin);
    }

    /// Demonstrates the vulnerability: the zero address is silently accepted.
    #[test]
    fn test_zero_address_accepted_as_admin() {
        let (env, client) = setup();
        let zero = Address::from_string(&String::from_str(&env, ZERO_ADDR));
        client.initialize(&zero);
        assert_eq!(client.get_admin(), zero);
    }

    /// Demonstrates the consequence: admin functions are permanently inaccessible
    /// because no real signer can provide auth for the zero address.
    #[test]
    #[should_panic]
    fn test_admin_functions_permanently_inaccessible() {
        let (env, client) = setup();
        let zero = Address::from_string(&String::from_str(&env, ZERO_ADDR));
        client.initialize(&zero);
        // No auth can be provided for the zero address — panics.
        client.set_value(&42);
    }
}
