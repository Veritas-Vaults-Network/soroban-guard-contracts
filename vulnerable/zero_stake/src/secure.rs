//! SECURE mirror: reject zero-amount stakes before touching storage.

use crate::{DataKey, StakeInfo};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureStaking;

#[contractimpl]
impl SecureStaking {
    /// ✅ Fixed: panics immediately if `amount` is not positive.
    pub fn stake(env: Env, staker: Address, amount: i128) {
        staker.require_auth();
        // ✅ Guard prevents ghost staker entries.
        assert!(amount > 0, "stake must be positive");
        env.storage().persistent().set(
            &DataKey::Stake(staker),
            &StakeInfo {
                amount,
                staked_at: env.ledger().timestamp(),
            },
        );
    }

    pub fn claim_rewards(env: Env, staker: Address) -> i128 {
        let info: StakeInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Stake(staker))
            .expect("no stake found");
        let elapsed = env.ledger().timestamp().saturating_sub(info.staked_at) as i128;
        info.amount * elapsed
    }

    pub fn is_staker(env: Env, staker: Address) -> bool {
        env.storage().persistent().has(&DataKey::Stake(staker))
    }
}
