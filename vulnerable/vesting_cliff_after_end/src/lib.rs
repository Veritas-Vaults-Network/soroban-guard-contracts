//! VULNERABLE: Vesting Cliff After End
//!
//! A linear vesting contract with a cliff, closely mirroring
//! `secure/secure_vesting`, except for one missing check.
//!
//! VULNERABILITY: `create_schedule` never validates that `cliff_ledger <
//! end_ledger` before storing the schedule (it only checks `total > 0`).
//! This lets an admin — via a plausible real-world mistake such as swapped
//! function arguments or a config file with the two fields transposed —
//! create a schedule where `cliff_ledger > end_ledger`.
//!
//! Impact, in two parts:
//! 1. For the entire window between the intended `end_ledger` and the
//!    erroneous (larger) `cliff_ledger`, `vested_for_schedule` returns 0,
//!    because the FIRST check (`now < cliff_ledger`) is still true. The
//!    beneficiary's funds are locked far longer than the schedule was meant
//!    to promise — well past the date the grant should have fully vested.
//! 2. The instant `now` reaches the erroneous (larger) `cliff_ledger`
//!    value, the SECOND check (`now >= end_ledger`) is also already true,
//!    so the beneficiary receives the ENTIRE `total` allocation in one
//!    shot — a sudden full unlock with zero gradual vesting, exactly the
//!    "instant dump" risk that linear vesting exists to prevent.
//!
//! SEVERITY: High

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

#[derive(Clone)]
#[contracttype]
pub struct VestingSchedule {
    pub total: i128,
    pub claimed: i128,
    pub cliff_ledger: u32,
    pub end_ledger: u32,
}

#[contracttype]
pub enum DataKey {
    Admin,
    Token,
    Schedule(Address),
}

#[contract]
pub struct VestingCliffAfterEnd;

#[contractimpl]
impl VestingCliffAfterEnd {
    pub fn initialize(env: Env, admin: Address, token: Address) {
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Token, &token);
    }

    /// VULNERABLE: only checks `total > 0`. Unlike `secure/secure_vesting`,
    /// there is no `if cliff_ledger >= end_ledger { panic!(...) }` guard, so
    /// a schedule with `cliff_ledger > end_ledger` is accepted and stored.
    pub fn create_schedule(
        env: Env,
        beneficiary: Address,
        total: i128,
        cliff_ledger: u32,
        end_ledger: u32,
    ) {
        Self::require_admin_auth(&env);
        if total <= 0 {
            panic!("total must be positive");
        }
        // ❌ Missing: if cliff_ledger >= end_ledger { panic!("invalid schedule") }

        let key = DataKey::Schedule(beneficiary);
        if env.storage().persistent().has(&key) {
            panic!("schedule already exists");
        }

        let schedule = VestingSchedule {
            total,
            claimed: 0,
            cliff_ledger,
            end_ledger,
        };
        env.storage().persistent().set(&key, &schedule);
    }

    /// Admin deposits tokens into the contract so it can actually pay out claims.
    pub fn fund(env: Env, amount: i128) {
        Self::require_admin_auth(&env);
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("contract not initialized");
        let token: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Token)
            .expect("contract not initialized");
        token::Client::new(&env, &token).transfer(&admin, &env.current_contract_address(), &amount);
    }

    pub fn claim(env: Env, beneficiary: Address) -> i128 {
        beneficiary.require_auth();

        let key = DataKey::Schedule(beneficiary.clone());
        let mut schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&key)
            .expect("schedule not found");

        let vested = Self::vested_for_schedule(&env, &schedule);
        if vested <= schedule.claimed {
            panic!("nothing claimable");
        }

        let claimable = vested - schedule.claimed;
        schedule.claimed = vested;
        env.storage().persistent().set(&key, &schedule);

        let token: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Token)
            .expect("contract not initialized");
        token::Client::new(&env, &token).transfer(
            &env.current_contract_address(),
            &beneficiary,
            &claimable,
        );

        claimable
    }

    pub fn vested_amount(env: Env, beneficiary: Address) -> i128 {
        let schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&DataKey::Schedule(beneficiary))
            .expect("schedule not found");
        Self::vested_for_schedule(&env, &schedule)
    }

    pub fn get_position(env: Env, beneficiary: Address) -> (i128, i128) {
        let schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&DataKey::Schedule(beneficiary))
            .expect("schedule not found");
        (schedule.total, schedule.claimed)
    }

    /// Vesting curve, copied verbatim from `secure/secure_vesting`. The math
    /// here is correct in isolation — the bug lives entirely in
    /// `create_schedule`'s missing input validation, not in this function.
    fn vested_for_schedule(env: &Env, schedule: &VestingSchedule) -> i128 {
        let now = env.ledger().sequence();

        if now < schedule.cliff_ledger {
            return 0;
        }
        if now >= schedule.end_ledger {
            return schedule.total;
        }
        let elapsed = (now - schedule.cliff_ledger) as i128;
        let duration = (schedule.end_ledger - schedule.cliff_ledger) as i128;
        schedule.total * elapsed / duration
    }

    fn require_admin_auth(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("contract not initialized");
        admin.require_auth();
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use soroban_sdk::{
        testutils::Address as _,
        testutils::Ledger as _,
        token::{Client as TokenClient, StellarAssetClient},
        Address, Env,
    };

    fn setup() -> (
        Env,
        VestingCliffAfterEndClient<'static>,
        Address,
        Address,
        Address,
    ) {
        let env = Env::default();
        env.mock_all_auths();

        let token_admin = Address::generate(&env);
        let token_id = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();

        let contract_id = env.register_contract(None, VestingCliffAfterEnd);
        let client = VestingCliffAfterEndClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let beneficiary = Address::generate(&env);

        // Mint tokens to the admin so it can fund the vesting contract.
        StellarAssetClient::new(&env, &token_id).mint(&admin, &10_000);

        (env, client, admin, beneficiary, token_id)
    }

    /// Control case: a normal, correctly-ordered schedule still vests
    /// linearly as expected. This proves the vesting MATH is fine — the bug
    /// is purely about missing input validation in `create_schedule`.
    #[test]
    fn test_control_normal_schedule_still_vests_linearly() {
        let (env, client, admin, beneficiary, token_id) = setup();
        env.ledger().set_sequence_number(100);

        client.initialize(&admin, &token_id);
        client.create_schedule(&beneficiary, &1_000, &200, &400);

        env.ledger().set_sequence_number(150);
        assert_eq!(client.vested_amount(&beneficiary), 0);

        // Mid-schedule: vested = 1000 * (300 - 200) / (400 - 200) = 500.
        env.ledger().set_sequence_number(300);
        assert_eq!(client.vested_amount(&beneficiary), 500);

        env.ledger().set_sequence_number(400);
        assert_eq!(client.vested_amount(&beneficiary), 1_000);
    }

    /// Demonstrates the missing validation: a schedule with `cliff_ledger`
    /// and `end_ledger` swapped (cliff = 400, end = 200) is accepted without
    /// panicking, unlike what would happen against a properly-validated
    /// contract such as `secure/secure_vesting`.
    #[test]
    fn test_swapped_cliff_and_end_accepted_bug() {
        let (env, client, admin, beneficiary, token_id) = setup();
        env.ledger().set_sequence_number(100);

        client.initialize(&admin, &token_id);
        client.create_schedule(&beneficiary, &1_000, &400, &200);

        let (total, claimed) = client.get_position(&beneficiary);
        assert_eq!(total, 1_000);
        assert_eq!(claimed, 0);
    }

    /// With the swapped schedule (cliff = 400, end = 200), at ledger 200 —
    /// the date the grant was SUPPOSED to be fully vested — the beneficiary
    /// has received nothing at all, because `now < cliff_ledger` is still
    /// true. Funds are locked well past their promised full-vesting date.
    #[test]
    fn test_funds_locked_past_intended_full_vest_date_bug() {
        let (env, client, admin, beneficiary, token_id) = setup();
        env.ledger().set_sequence_number(100);

        client.initialize(&admin, &token_id);
        client.create_schedule(&beneficiary, &1_000, &400, &200);

        env.ledger().set_sequence_number(200);
        assert_eq!(client.vested_amount(&beneficiary), 0);
    }

    /// With the same swapped schedule, the instant `now` reaches the
    /// erroneous (later) "cliff" of 400, the entire allocation unlocks in
    /// one shot — zero gradual vesting ever occurred, defeating the purpose
    /// of a linear vesting schedule.
    #[test]
    fn test_instant_full_unlock_at_erroneous_cliff_bug() {
        let (env, client, admin, beneficiary, token_id) = setup();
        env.ledger().set_sequence_number(100);

        client.initialize(&admin, &token_id);
        client.create_schedule(&beneficiary, &1_000, &400, &200);

        env.ledger().set_sequence_number(400);
        assert_eq!(client.vested_amount(&beneficiary), 1_000);
    }

    /// End-to-end demonstration: `claim()` at the erroneous cliff actually
    /// pays out the full 1000 in a single transfer.
    #[test]
    fn test_claim_pays_out_full_amount_at_erroneous_cliff_bug() {
        let (env, client, admin, beneficiary, token_id) = setup();
        env.ledger().set_sequence_number(100);

        client.initialize(&admin, &token_id);
        client.create_schedule(&beneficiary, &1_000, &400, &200);
        client.fund(&1_000);

        env.ledger().set_sequence_number(400);
        let claimed = client.claim(&beneficiary);
        assert_eq!(claimed, 1_000);

        let beneficiary_balance = TokenClient::new(&env, &token_id).balance(&beneficiary);
        assert_eq!(beneficiary_balance, 1_000);
    }
}
