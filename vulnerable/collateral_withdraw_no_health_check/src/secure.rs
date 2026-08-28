//! SECURE mirror: verifies that remaining collateral after withdrawal satisfies
//! the loan-to-value (LTV) health check for any outstanding debt.

use crate::DataKey;
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct SecureCollateralLendingPool;

#[contractimpl]
impl SecureCollateralLendingPool {
    pub fn initialize(env: Env, admin: Address, collateral_price_usd: i128, max_ltv_bps: u32) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        admin.require_auth();
        assert!(collateral_price_usd > 0, "price must be positive");
        assert!(max_ltv_bps > 0 && max_ltv_bps <= 10_000, "invalid ltv bps");

        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::CollateralPriceUsd, &collateral_price_usd);
        env.storage()
            .persistent()
            .set(&DataKey::MaxLtvBps, &max_ltv_bps);
    }

    pub fn deposit_collateral(env: Env, user: Address, amount: i128) {
        user.require_auth();
        assert!(amount > 0, "amount must be positive");

        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Collateral(user.clone()))
            .unwrap_or(0);
        let new_collateral = current.checked_add(amount).expect("overflow");
        env.storage()
            .persistent()
            .set(&DataKey::Collateral(user.clone()), &new_collateral);

        env.events()
            .publish((symbol_short!("deposit"), user), amount);
    }

    pub fn borrow(env: Env, user: Address, amount: i128) -> i128 {
        user.require_auth();
        assert!(amount > 0, "amount must be positive");

        let collateral: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Collateral(user.clone()))
            .unwrap_or(0);
        let debt: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Debt(user.clone()))
            .unwrap_or(0);

        let price: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::CollateralPriceUsd)
            .expect("not initialized");
        let ltv_bps: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::MaxLtvBps)
            .expect("not initialized");

        let collateral_value_usd = collateral.checked_mul(price).expect("overflow") / 1_000_000;
        let max_borrow = collateral_value_usd
            .checked_mul(ltv_bps as i128)
            .expect("overflow")
            / 10_000;

        let new_debt = debt.checked_add(amount).expect("overflow");
        assert!(new_debt <= max_borrow, "insufficient collateral for borrow");

        env.storage()
            .persistent()
            .set(&DataKey::Debt(user.clone()), &new_debt);

        env.events()
            .publish((symbol_short!("borrow"), user), amount);
        amount
    }

    pub fn repay(env: Env, user: Address, amount: i128) -> i128 {
        user.require_auth();
        assert!(amount > 0, "amount must be positive");

        let debt: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Debt(user.clone()))
            .unwrap_or(0);
        assert!(debt > 0, "no outstanding debt");

        let to_repay = if amount > debt { debt } else { amount };
        let new_debt = debt.checked_sub(to_repay).expect("underflow");

        env.storage()
            .persistent()
            .set(&DataKey::Debt(user.clone()), &new_debt);

        env.events()
            .publish((symbol_short!("repay"), user), to_repay);
        to_repay
    }

    /// ✅ FIX: Enforces health check on remaining collateral before allowing withdrawal.
    pub fn withdraw_collateral(env: Env, user: Address, amount: i128) {
        user.require_auth();
        assert!(amount > 0, "amount must be positive");

        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Collateral(user.clone()))
            .unwrap_or(0);
        assert!(current >= amount, "insufficient collateral balance");

        let remaining_collateral = current.checked_sub(amount).expect("underflow");
        let debt: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Debt(user.clone()))
            .unwrap_or(0);

        // ✅ Health check: verify remaining collateral is sufficient to support existing debt
        if debt > 0 {
            let price: i128 = env
                .storage()
                .persistent()
                .get(&DataKey::CollateralPriceUsd)
                .expect("not initialized");
            let ltv_bps: u32 = env
                .storage()
                .persistent()
                .get(&DataKey::MaxLtvBps)
                .expect("not initialized");

            let remaining_value_usd =
                remaining_collateral.checked_mul(price).expect("overflow") / 1_000_000;
            let max_supported_debt = remaining_value_usd
                .checked_mul(ltv_bps as i128)
                .expect("overflow")
                / 10_000;

            assert!(
                debt <= max_supported_debt,
                "health check failed: remaining collateral cannot cover debt"
            );
        }

        env.storage()
            .persistent()
            .set(&DataKey::Collateral(user.clone()), &remaining_collateral);

        env.events()
            .publish((symbol_short!("withdraw"), user), amount);
    }

    pub fn get_collateral(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Collateral(user))
            .unwrap_or(0)
    }

    pub fn get_debt(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Debt(user))
            .unwrap_or(0)
    }
}
