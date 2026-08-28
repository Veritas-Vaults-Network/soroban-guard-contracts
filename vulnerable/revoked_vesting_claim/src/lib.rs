//! VULNERABLE: Revoked Vesting Claim
//!
//! A revocable vesting contract where `revoke()` correctly computes the
//! unvested balance at the time of revocation and credits it to the
//! treasury's bookkeeping balance — but that is where the fix stops.
//! `vested_for_schedule()` (the function that both `vested_amount()` and
//! `claim()` rely on to determine how much the beneficiary may withdraw)
//! never references `revoked_at` at all, and `claim()` never checks whether
//! the schedule has been revoked before paying out. The result is that a
//! "revoked" beneficiary's vesting curve keeps running exactly as if nothing
//! happened.
//!
//! VULNERABILITY: `revoke()` moves `total - vested_at_revocation` into
//! `TreasuryBalance`, but `vested_for_schedule()` computes vesting purely
//! from `env.ledger().sequence()` with no cap at `revoked_at`, and `claim()`
//! never checks `schedule.revoked_at.is_some()`. Once the ledger sequence
//! passes `end_ledger`, the (supposedly terminated) beneficiary can still
//! claim their full original `total` grant — on top of the unvested portion
//! the admin already reclaimed to the treasury. The same tokens are promised
//! twice: once to the treasury's bookkeeping and once to the beneficiary,
//! making the contract insolvent relative to what was ever funded for that
//! single grant.
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
    pub revoked_at: Option<u32>,
}

#[contracttype]
pub enum DataKey {
    Admin,
    Treasury,
    TreasuryBalance,
    Token,
    Schedule(Address),
}

#[contract]
pub struct RevokedVestingClaim;

#[contractimpl]
impl RevokedVestingClaim {
    pub fn initialize(env: Env, admin: Address, treasury: Address, token: Address) {
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::Treasury, &treasury);
        env.storage().persistent().set(&DataKey::Token, &token);
        env.storage()
            .persistent()
            .set(&DataKey::TreasuryBalance, &0i128);
    }

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
        if cliff_ledger >= end_ledger {
            panic!("invalid schedule");
        }

        let key = DataKey::Schedule(beneficiary);
        if env.storage().persistent().has(&key) {
            panic!("schedule already exists");
        }

        let schedule = VestingSchedule {
            total,
            claimed: 0,
            cliff_ledger,
            end_ledger,
            revoked_at: None,
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

    /// VULNERABLE: never checks `schedule.revoked_at` before paying out, and
    /// `vested_for_schedule` never caps `now` at `revoked_at` either — so a
    /// revoked beneficiary keeps vesting (and can eventually claim their
    /// full grant) exactly as if `revoke()` had never been called.
    pub fn claim(env: Env, beneficiary: Address) -> i128 {
        beneficiary.require_auth();

        let key = DataKey::Schedule(beneficiary.clone());
        let mut schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&key)
            .expect("schedule not found");

        // ❌ Missing: panic!("schedule revoked") when schedule.revoked_at.is_some()

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

    pub fn revoke(env: Env, beneficiary: Address) {
        Self::require_admin_auth(&env);

        let key = DataKey::Schedule(beneficiary);
        let mut schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&key)
            .expect("schedule not found");
        if schedule.revoked_at.is_some() {
            panic!("already revoked");
        }

        let now = env.ledger().sequence();
        let vested_now = Self::vested_for_schedule(&env, &schedule);
        let unvested = schedule.total - vested_now;

        let current_treasury_balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TreasuryBalance)
            .unwrap_or(0);
        env.storage().persistent().set(
            &DataKey::TreasuryBalance,
            &(current_treasury_balance + unvested),
        );

        schedule.revoked_at = Some(now);
        env.storage().persistent().set(&key, &schedule);
    }

    pub fn vested_amount(env: Env, beneficiary: Address) -> i128 {
        let schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&DataKey::Schedule(beneficiary))
            .expect("schedule not found");
        Self::vested_for_schedule(&env, &schedule)
    }

    pub fn get_position(env: Env, beneficiary: Address) -> (i128, i128, bool) {
        let schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&DataKey::Schedule(beneficiary))
            .expect("schedule not found");
        (
            schedule.total,
            schedule.claimed,
            schedule.revoked_at.is_some(),
        )
    }

    pub fn treasury_balance(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TreasuryBalance)
            .unwrap_or(0)
    }

    /// VULNERABLE: unlike the secure reference implementation, this never
    /// caps `now` at `schedule.revoked_at` — vesting keeps accruing on the
    /// beneficiary's original curve forever, even after `revoke()` has run.
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
        RevokedVestingClaimClient<'static>,
        Address,
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

        let contract_id = env.register_contract(None, RevokedVestingClaim);
        let client = RevokedVestingClaimClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let beneficiary = Address::generate(&env);

        // Mint tokens to the admin so it can fund the vesting contract.
        StellarAssetClient::new(&env, &token_id).mint(&admin, &10_000);

        (env, client, admin, treasury, beneficiary, token_id)
    }

    #[test]
    fn test_control_revoke_correctly_moves_unvested_to_treasury_bookkeeping() {
        let (env, client, admin, treasury, beneficiary, token_id) = setup();
        env.ledger().set_sequence_number(100);

        client.initialize(&admin, &treasury, &token_id);
        client.create_schedule(&beneficiary, &1_000, &200, &400);

        // At ledger 250, vested = 1000 * (250 - 200) / (400 - 200) = 250, unvested = 750.
        env.ledger().set_sequence_number(250);
        client.revoke(&beneficiary);
        assert_eq!(client.treasury_balance(), 750);
    }

    /// Demonstrates the exploit: `revoke()` correctly reclaims 750 to the
    /// treasury's bookkeeping, but because `vested_for_schedule`/`claim`
    /// never reference `revoked_at`, the beneficiary can still claim the
    /// FULL 1000 total once `now >= end_ledger` — the same tokens end up
    /// promised twice, and the contract is insolvent relative to the 1000
    /// it was ever funded for on this grant.
    #[test]
    fn test_revoked_beneficiary_still_claims_full_amount_bug() {
        let (env, client, admin, treasury, beneficiary, token_id) = setup();
        env.ledger().set_sequence_number(100);

        client.initialize(&admin, &treasury, &token_id);
        client.create_schedule(&beneficiary, &1_000, &200, &400);
        client.fund(&1_000);

        // At ledger 250, vested = 250, unvested = 750 is reclaimed to treasury.
        env.ledger().set_sequence_number(250);
        client.revoke(&beneficiary);
        assert_eq!(client.treasury_balance(), 750);

        // Past end_ledger, the "revoked" beneficiary still claims the FULL
        // original grant, since vested_for_schedule ignores revoked_at.
        env.ledger().set_sequence_number(500);
        let claimed = client.claim(&beneficiary);
        assert_eq!(claimed, 1_000);

        let beneficiary_balance = TokenClient::new(&env, &token_id).balance(&beneficiary);
        assert_eq!(beneficiary_balance, 1_000);

        // Insolvency: the treasury bookkeeping (750) plus what the
        // beneficiary actually received (1000) exceeds the 1000 tokens ever
        // funded for this single grant.
        let total_promised = client.treasury_balance() + beneficiary_balance;
        assert!(
            total_promised > 1_000,
            "expected insolvency: treasury_balance + beneficiary payout ({}) should exceed the funded total (1000)",
            total_promised
        );
        assert_eq!(total_promised, 1_750);
    }
}
