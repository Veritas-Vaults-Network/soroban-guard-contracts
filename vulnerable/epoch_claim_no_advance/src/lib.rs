//! VULNERABLE: Epoch-Advance Keeper Missing a Time Guard
//!
//! An epoch-based staking reward distributor (MasterChef-style accumulator).
//! Rewards accrue via a `reward_per_share` accumulator that is meant to be
//! pushed forward by exactly one epoch's worth of reward each time a real
//! epoch elapses. A permissionless "keeper" function, `advance_epoch()`, is
//! intentionally open to anyone to call — no access control is needed for it
//! in a correct design, since the function is only supposed to *reflect* the
//! passage of real time, not create value on its own.
//!
//! VULNERABILITY: `advance_epoch()` has no
//! `require(now >= last_advance_time + epoch_length)`-style guard at all.
//! Nothing stops it from being invoked an unbounded number of times back to
//! back, within a single ledger/second, with zero real time elapsing between
//! calls. Each call unconditionally adds one full epoch's worth of reward to
//! `reward_per_share`. Because the function is deliberately permissionless,
//! any single staker (or indeed anyone, staked or not) can call it in a tight
//! loop to inflate the accumulator arbitrarily, then `claim()` a payout many
//! multiples larger than a single real epoch would ever justify — draining
//! the entire funded reward pool immediately, regardless of how long the
//! pool was meant to last.
//!
//! SEVERITY: Critical

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, token, Address, Env};

/// Fixed-point scale for `RewardPerShare` (1e12).
pub const PRECISION: i128 = 1_000_000_000_000;

#[contracttype]
pub enum DataKey {
    Admin,
    Token,
    /// Total amount currently staked across all stakers.
    TotalStaked,
    /// Global accumulator: cumulative reward per staked token, scaled by `PRECISION`.
    RewardPerShare,
    /// Fixed reward amount distributed per epoch tick.
    EpochRewardAmount,
    /// Amount staked by each staker.
    Stake(Address),
    /// Snapshot of `stake * RewardPerShare / PRECISION` at last deposit/claim.
    RewardDebt(Address),
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

fn get_total_staked(env: &Env) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::TotalStaked)
        .unwrap_or(0)
}

fn set_total_staked(env: &Env, value: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::TotalStaked, &value);
}

fn get_reward_per_share(env: &Env) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::RewardPerShare)
        .unwrap_or(0)
}

fn set_reward_per_share(env: &Env, value: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::RewardPerShare, &value);
}

fn get_epoch_reward_amount(env: &Env) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::EpochRewardAmount)
        .unwrap_or(0)
}

fn get_stake(env: &Env, staker: &Address) -> Option<i128> {
    env.storage()
        .persistent()
        .get(&DataKey::Stake(staker.clone()))
}

fn set_stake(env: &Env, staker: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Stake(staker.clone()), &amount);
}

fn get_reward_debt(env: &Env, staker: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::RewardDebt(staker.clone()))
        .unwrap_or(0)
}

fn set_reward_debt(env: &Env, staker: &Address, debt: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::RewardDebt(staker.clone()), &debt);
}

fn compute_pending(env: &Env, staker: &Address) -> i128 {
    let stake = get_stake(env, staker).expect("not staked");
    let accrued = stake * get_reward_per_share(env) / PRECISION;
    accrued - get_reward_debt(env, staker)
}

#[contract]
pub struct EpochStaking;

#[contractimpl]
impl EpochStaking {
    /// Initialize the pool with an admin, reward token, and fixed per-epoch
    /// reward amount.
    pub fn initialize(env: Env, admin: Address, token: Address, epoch_reward_amount: i128) {
        admin.require_auth();
        assert!(
            !env.storage().persistent().has(&DataKey::Admin),
            "already initialized"
        );
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Token, &token);
        env.storage()
            .persistent()
            .set(&DataKey::EpochRewardAmount, &epoch_reward_amount);
        set_total_staked(&env, 0);
        set_reward_per_share(&env, 0);
    }

    /// Admin funds the contract's reward pool.
    pub fn fund(env: Env, amount: i128) {
        let admin = get_admin(&env);
        admin.require_auth();
        let token = get_token(&env);
        token::Client::new(&env, &token).transfer(&admin, &env.current_contract_address(), &amount);
    }

    /// Stake tokens. One stake per address (no top-ups), so no mid-stream
    /// reward settlement is needed.
    pub fn stake(env: Env, staker: Address, amount: i128) {
        staker.require_auth();
        assert!(amount > 0, "amount must be positive");
        assert!(get_stake(&env, &staker).is_none(), "already staked");

        let token = get_token(&env);
        token::Client::new(&env, &token).transfer(
            &staker,
            &env.current_contract_address(),
            &amount,
        );

        set_stake(&env, &staker, amount);
        // Snapshot the accumulator so the staker doesn't retroactively earn
        // rewards that accrued before they joined.
        let debt = amount * get_reward_per_share(&env) / PRECISION;
        set_reward_debt(&env, &staker, debt);

        set_total_staked(&env, get_total_staked(&env) + amount);
    }

    /// Permissionless keeper function meant to be called once per epoch to
    /// push the reward accumulator forward. No access control is required by
    /// design — anyone may call it to reflect the passage of time.
    ///
    /// # Vulnerability
    /// Missing a `require(now >= last_advance_time + epoch_length)`-style
    /// time guard. Nothing prevents calling this function an unbounded
    /// number of times with zero real time elapsed between calls, each call
    /// adding a full epoch's worth of reward to `RewardPerShare`. Impact:
    /// unlimited reward-pool drain via a tight call loop.
    pub fn advance_epoch(env: Env) {
        let total_staked = get_total_staked(&env);
        assert!(total_staked > 0, "no stakers");

        // ❌ VULNERABLE: no timestamp/sequence check of any kind here.
        // let last = get_last_advance_time(&env);
        // let epoch_length = get_epoch_length(&env);
        // assert!(env.ledger().timestamp() >= last + epoch_length, "epoch not elapsed");
        // set_last_advance_time(&env, env.ledger().timestamp());

        let delta = get_epoch_reward_amount(&env) * PRECISION / total_staked;
        set_reward_per_share(&env, get_reward_per_share(&env) + delta);
    }

    /// Claim all currently pending rewards.
    pub fn claim(env: Env, staker: Address) -> i128 {
        staker.require_auth();
        let stake = get_stake(&env, &staker).expect("not staked");
        let pending = compute_pending(&env, &staker);
        assert!(pending > 0, "nothing to claim");

        let entitled = stake * get_reward_per_share(&env) / PRECISION;
        set_reward_debt(&env, &staker, entitled);

        let token = get_token(&env);
        token::Client::new(&env, &token).transfer(
            &env.current_contract_address(),
            &staker,
            &pending,
        );

        env.events()
            .publish((symbol_short!("claim"),), (staker, pending));

        pending
    }

    /// View helper: pending reward for `staker` without mutating state.
    pub fn pending_reward(env: Env, staker: Address) -> i128 {
        compute_pending(&env, &staker)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::Address as _,
        token::{Client as TokenClient, StellarAssetClient},
        Address, Env,
    };

    fn setup() -> (Env, EpochStakingClient<'static>, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let staker = Address::generate(&env);

        let token_admin = Address::generate(&env);
        let token_id = env
            .register_stellar_asset_contract_v2(token_admin.clone())
            .address();
        StellarAssetClient::new(&env, &token_id).mint(&admin, &1_000_000);
        StellarAssetClient::new(&env, &token_id).mint(&staker, &1_000_000);

        let contract_id = env.register_contract(None, EpochStaking);
        let client = EpochStakingClient::new(&env, &contract_id);

        client.initialize(&admin, &token_id, &100);
        client.fund(&1_000_000);
        client.stake(&staker, &100);

        (env, client, token_id, admin, staker)
    }

    /// Control: a single legitimate `advance_epoch()` tick pays out exactly
    /// one epoch's worth of reward.
    #[test]
    fn test_control_single_epoch_advance_pays_correct_reward() {
        let (env, client, token_id, _admin, staker) = setup();

        client.advance_epoch();
        let reward = client.claim(&staker);

        assert_eq!(reward, 100);
        assert_eq!(
            TokenClient::new(&env, &token_id).balance(&staker),
            1_000_000 - 100 + 100
        );
    }

    /// Demonstrates the bug: calling `advance_epoch()` repeatedly with zero
    /// real time elapsed between calls inflates the accumulator without
    /// bound, letting the staker claim many epochs' worth of reward
    /// immediately.
    #[test]
    fn test_repeated_advance_epoch_without_time_passing_drains_pool_bug() {
        let (_env, client, _token_id, _admin, staker) = setup();

        for _ in 0..50 {
            client.advance_epoch();
        }

        let reward = client.claim(&staker);
        assert_eq!(
            reward, 5000,
            "bug: 50 back-to-back advances paid out 50 epochs' worth with no time elapsed"
        );
    }
}
