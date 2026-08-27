//! VULNERABLE: Vesting Claim Never Persists Its Running Total
//!
//! A linear vesting contract where `claim()` correctly *computes* the
//! claimable amount as `claimable = vested - claimed`, pays it out, and
//! returns it — but never writes the updated `claimed` total back to
//! storage. `schedule.claimed` is mutated only in the caller's local stack
//! frame (or not mutated at all), so the persisted schedule's `claimed`
//! field is permanently stuck at its initial value of `0`.
//!
//! VULNERABILITY: `claim()` is missing the
//! `env.storage().persistent().set(&key, &schedule)` write-back (with
//! `schedule.claimed` advanced to `vested`) that a correct implementation
//! requires immediately after computing `claimable`.
//!
//! SEVERITY: Critical
//!
//! Impact: because `claimed` never advances, every single call to `claim()`
//! — no matter how many times in a row, even within the exact same ledger
//! sequence — recomputes `claimable = vested - 0` and re-pays the *entire*
//! currently-vested amount again, not just the newly-vested increment since
//! the last claim. Calling `claim()` repeatedly drains the contract far
//! beyond the beneficiary's actual allocation, unboundedly — limited only by
//! the contract's remaining token balance.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, token, Address, Env};

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

fn get_admin(env: &Env) -> Address {
    env.storage()
        .persistent()
        .get(&DataKey::Admin)
        .expect("not initialized")
}

fn get_token(env: &Env) -> Address {
    env.storage()
        .persistent()
        .get(&DataKey::Token)
        .expect("not initialized")
}

#[contract]
pub struct VestingClaimedNotSubtracted;

#[contractimpl]
impl VestingClaimedNotSubtracted {
    /// Initialize the contract with an admin and the SAC token used for vesting payouts.
    pub fn initialize(env: Env, admin: Address, token: Address) {
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Token, &token);
    }

    /// Admin funds the contract so it can pay out vested tokens.
    pub fn fund(env: Env, amount: i128) {
        let admin = get_admin(&env);
        admin.require_auth();
        let token_id = get_token(&env);
        token::Client::new(&env, &token_id).transfer(
            &admin,
            &env.current_contract_address(),
            &amount,
        );
    }

    /// Admin creates a linear vesting schedule for `beneficiary`.
    pub fn create_schedule(
        env: Env,
        beneficiary: Address,
        total: i128,
        cliff_ledger: u32,
        end_ledger: u32,
    ) {
        let admin = get_admin(&env);
        admin.require_auth();

        assert!(total > 0, "total must be positive");
        assert!(cliff_ledger < end_ledger, "invalid schedule");

        let key = DataKey::Schedule(beneficiary);
        assert!(
            !env.storage().persistent().has(&key),
            "schedule already exists"
        );

        let schedule = VestingSchedule {
            total,
            claimed: 0,
            cliff_ledger,
            end_ledger,
        };
        env.storage().persistent().set(&key, &schedule);
    }

    /// VULNERABLE: computes and pays `claimable = vested - claimed`
    /// correctly, but never persists the updated `claimed` total back to
    /// storage. `claimed` never advances, so repeated calls at the same (or
    /// later) vesting point re-pay the entire currently-vested amount every
    /// time.
    ///
    /// # Vulnerability
    /// Missing `env.storage().persistent().set(&key, &schedule)` (with
    /// `schedule.claimed` advanced to `vested`) after computing `claimable`.
    /// Impact: unbounded reward drain via repeated calls to `claim()`.
    pub fn claim(env: Env, beneficiary: Address) -> i128 {
        beneficiary.require_auth();

        let key = DataKey::Schedule(beneficiary.clone());
        let schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&key)
            .expect("schedule not found");

        let vested = Self::vested_for_schedule(&env, &schedule);
        let claimable = vested - schedule.claimed;
        if claimable <= 0 {
            panic!("nothing claimable");
        }

        // ❌ VULNERABLE: `schedule.claimed` is never advanced to `vested`,
        // and the schedule is never written back to storage. The persisted
        // `claimed` field stays at 0 forever, no matter how many times this
        // function is called.
        // schedule.claimed = vested;
        // env.storage().persistent().set(&key, &schedule);

        let token_id = get_token(&env);
        token::Client::new(&env, &token_id).transfer(
            &env.current_contract_address(),
            &beneficiary,
            &claimable,
        );

        env.events()
            .publish((symbol_short!("claim"),), (beneficiary, claimable));

        claimable
    }

    /// View helper: total vested (not net of claims) for `beneficiary` at the current ledger.
    pub fn vested_amount(env: Env, beneficiary: Address) -> i128 {
        let schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&DataKey::Schedule(beneficiary))
            .expect("schedule not found");
        Self::vested_for_schedule(&env, &schedule)
    }

    /// View helper: `(total, claimed)` for `beneficiary`'s schedule.
    pub fn get_position(env: Env, beneficiary: Address) -> (i128, i128) {
        let schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&DataKey::Schedule(beneficiary))
            .expect("schedule not found");
        (schedule.total, schedule.claimed)
    }

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
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger as _},
        token::{Client as TokenClient, StellarAssetClient},
        Address, Env,
    };

    fn setup() -> (
        Env,
        VestingClaimedNotSubtractedClient<'static>,
        Address,
        Address,
    ) {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let beneficiary = Address::generate(&env);

        let token_admin = Address::generate(&env);
        let token_id = env
            .register_stellar_asset_contract_v2(token_admin.clone())
            .address();
        StellarAssetClient::new(&env, &token_id).mint(&admin, &10_000);

        let contract_id = env.register_contract(None, VestingClaimedNotSubtracted);
        let client = VestingClaimedNotSubtractedClient::new(&env, &contract_id);

        client.initialize(&admin, &token_id);
        client.fund(&10_000);
        client.create_schedule(&beneficiary, &1_000, &0, &1_000);

        (env, client, token_id, beneficiary)
    }

    /// Control: a single claim at 50% vested pays exactly the vested amount.
    /// This alone does not reveal the bug - a single claim looks completely
    /// correct, which is exactly the point: the bug only shows up on repeat.
    #[test]
    fn test_control_single_claim_pays_correct_vested_amount() {
        let (env, client, token_id, beneficiary) = setup();

        env.ledger().set_sequence_number(500);
        let claimed = client.claim(&beneficiary);

        assert_eq!(claimed, 500);
        assert_eq!(TokenClient::new(&env, &token_id).balance(&beneficiary), 500);
    }

    /// Demonstrates the bug: three claims in a row at the *same* vesting
    /// point (sequence unchanged, vested stays 500 each time) each
    /// independently pay out the full 500, because `claimed` is never
    /// persisted back to storage after the first payout.
    #[test]
    fn test_repeated_claim_at_same_vesting_point_drains_far_beyond_allocation_bug() {
        let (env, client, token_id, beneficiary) = setup();

        env.ledger().set_sequence_number(500);

        let first = client.claim(&beneficiary);
        let second = client.claim(&beneficiary);
        let third = client.claim(&beneficiary);

        assert_eq!(first, 500);
        assert_eq!(second, 500);
        assert_eq!(third, 500);

        assert_eq!(
            TokenClient::new(&env, &token_id).balance(&beneficiary),
            1_500,
            "bug: three claims at 50% vested paid out 1500 - 50% more than the entire 1000-token grant"
        );

        let (_total, claimed) = client.get_position(&beneficiary);
        assert_eq!(
            claimed, 0,
            "bug: the persisted `claimed` total never advances past 0"
        );
    }

    /// Demonstrates the bug is unbounded: once fully vested, five back-to-back
    /// claims each pay out the entire 1000-token grant again.
    #[test]
    fn test_repeated_claim_after_full_vesting_still_drains_unboundedly() {
        let (env, client, token_id, beneficiary) = setup();

        env.ledger().set_sequence_number(1_000);

        for _ in 0..5 {
            let claimed = client.claim(&beneficiary);
            assert_eq!(claimed, 1_000);
        }

        assert_eq!(
            TokenClient::new(&env, &token_id).balance(&beneficiary),
            5_000,
            "bug: five claims after full vesting paid out 5000 - five times the original 1000-token grant"
        );
    }
}
