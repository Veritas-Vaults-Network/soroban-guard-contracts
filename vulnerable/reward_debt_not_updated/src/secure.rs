//! SECURE: `claim_rewards` advances `reward_debt` after paying out pending.
//!
//! The only change from the vulnerable contract is a single line: after
//! computing `pending`, the user's debt snapshot is updated to the current
//! `entitled` value. This ensures each unit of accrued reward is paid out
//! exactly once — a repeated claim with no new rewards yields 0.

use super::{get_acc, get_debt, get_stake, set_debt, DataKey};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureStaking;

#[contractimpl]
impl SecureStaking {
    /// Seed the global accumulator (simulates rewards already accrued).
    pub fn initialize(env: Env, acc_reward_per_share: u64) {
        env.storage()
            .persistent()
            .set(&DataKey::AccRewardPerShare, &acc_reward_per_share);
    }

    /// Deposit stake and snapshot current debt correctly.
    pub fn stake(env: Env, user: Address, amount: u64) {
        user.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::Stake(user.clone()), &amount);
        let debt = get_acc(&env).saturating_mul(amount) / 1_000_0000;
        set_debt(&env, &user, debt);
    }

    /// Advance the global accumulator (called by keeper / admin).
    pub fn add_rewards(env: Env, reward_per_share_delta: u64) {
        let acc = get_acc(&env).saturating_add(reward_per_share_delta);
        env.storage()
            .persistent()
            .set(&DataKey::AccRewardPerShare, &acc);
    }

    /// SECURE: pays pending rewards and advances `reward_debt` to the current
    /// accumulator so the same window cannot be claimed twice.
    pub fn claim_rewards(env: Env, user: Address) -> u64 {
        user.require_auth();
        let stake = get_stake(&env, &user);
        let acc = get_acc(&env);
        let entitled = acc.saturating_mul(stake) / 1_000_0000;
        let debt = get_debt(&env, &user);
        let pending = entitled.saturating_sub(debt);
        // ✅ Advance debt so already-paid rewards can't be claimed again.
        set_debt(&env, &user, entitled);
        pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, SecureStakingClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SecureStaking);
        let client = SecureStakingClient::new(&env, &id);
        client.initialize(&0);
        let user = Address::generate(&env);
        client.stake(&user, &1_000);
        // Keeper adds rewards: 500 per share (×1e7 scaled → 5_000_000_000).
        client.add_rewards(&5_000_000_000);
        (env, client, user)
    }

    #[test]
    fn test_secure_claim_once_pays_correct_amount() {
        let (_env, client, user) = setup();
        // expected = (5_000_000_000 * 1_000) / 10_000_000 - 0 = 500_000
        let reward = client.claim_rewards(&user);
        assert_eq!(reward, 500_000, "first claim should equal acc × stake");
    }

    #[test]
    fn test_secure_second_claim_without_new_rewards_pays_zero() {
        let (_env, client, user) = setup();
        let first = client.claim_rewards(&user);
        assert_eq!(first, 500_000);
        // No new rewards distributed → debt already advanced → nothing pending.
        let second = client.claim_rewards(&user);
        assert_eq!(second, 0, "repeated claim without new rewards must pay 0");
    }

    #[test]
    fn test_secure_claim_after_new_distribution_pays_increment_only() {
        let (_env, client, user) = setup();
        let first = client.claim_rewards(&user);
        assert_eq!(first, 500_000);

        // Keeper distributes another 200 per share (×1e7 → 2_000_000_000).
        client.add_rewards(&2_000_000_000);
        let second = client.claim_rewards(&user);
        // Only the new increment: (2_000_000_000 * 1_000) / 10_000_000 = 200_000.
        assert_eq!(
            second, 200_000,
            "second claim must cover only the new increment, not the original amount"
        );
    }
}
