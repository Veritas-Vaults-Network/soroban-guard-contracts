//! VULNERABLE: Collateral Withdrawal Without Health Check
//!
//! A lending protocol allows users to deposit collateral (e.g. XLM) and borrow
//! loan tokens (e.g. USDC) against their deposited collateral based on a maximum
//! loan-to-value (LTV) ratio.
//!
//! When borrowing, the contract enforces that `debt <= collateral_value * ltv`.
//! However, when a user withdraws collateral via `withdraw_collateral()`, the contract
//! only checks that the user has enough deposited collateral to cover the withdrawal
//! amount (`amount <= user_collateral`), but completely fails to check whether the
//! remaining collateral still satisfies the health factor / LTV requirement for the
//! user's outstanding debt.
//!
//! VULNERABILITY: `withdraw_collateral` does not verify the borrower's health factor /
//! solvency after deducting the withdrawn collateral. A borrower can deposit collateral,
//! borrow up to the maximum LTV limit, and then immediately withdraw 100% of their
//! collateral, leaving the protocol with unbacked bad debt.
//!
//! SEVERITY: Critical

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[cfg(not(target_family = "wasm"))]
pub mod secure;

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    /// Price of 1 unit of collateral in USD (1e6 scale, e.g. 1_000_000 = $1.00).
    CollateralPriceUsd,
    /// Maximum Loan-To-Value in basis points (e.g. 7_500 = 75%).
    MaxLtvBps,
    /// User deposited collateral amount (in collateral token units).
    Collateral(Address),
    /// User borrowed debt amount in USD (1e6 scale).
    Debt(Address),
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct CollateralLendingPool;

#[contractimpl]
impl CollateralLendingPool {
    /// Initialize the lending pool with an admin, collateral USD price, and max LTV bps.
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

    /// Deposit collateral into the lending pool.
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

    /// Borrow USD debt against deposited collateral up to max LTV.
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

        // Calculate max borrow capacity: collateral * price * ltv_bps / (1e6 * 10_000)
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

    /// Repay borrowed USD debt.
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

    /// Withdraw deposited collateral.
    ///
    /// VULNERABILITY: Only checks `current_collateral >= amount`, but never validates
    /// whether the remaining collateral satisfies the solvency / LTV requirement for any
    /// active outstanding debt.
    pub fn withdraw_collateral(env: Env, user: Address, amount: i128) {
        user.require_auth();
        assert!(amount > 0, "amount must be positive");

        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Collateral(user.clone()))
            .unwrap_or(0);
        assert!(current >= amount, "insufficient collateral balance");

        // ❌ VULNERABILITY: Missing health check on remaining collateral!
        // A user with active debt can withdraw 100% of their collateral, leaving unbacked debt.
        let new_collateral = current.checked_sub(amount).expect("underflow");
        env.storage()
            .persistent()
            .set(&DataKey::Collateral(user.clone()), &new_collateral);

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

    pub fn get_max_borrow(env: Env, user: Address) -> i128 {
        let collateral = Self::get_collateral(env.clone(), user);
        let price: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::CollateralPriceUsd)
            .unwrap_or(0);
        let ltv_bps: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::MaxLtvBps)
            .unwrap_or(0);

        let collateral_value_usd = collateral.checked_mul(price).unwrap_or(0) / 1_000_000;
        collateral_value_usd
            .checked_mul(ltv_bps as i128)
            .unwrap_or(0)
            / 10_000
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, Address, CollateralLendingPoolClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let user = Address::generate(&env);
        let id = env.register_contract(None, CollateralLendingPool);
        let client = CollateralLendingPoolClient::new(&env, &id);

        // Initialize: collateral price = $2.00 (2_000_000 at 1e6 scale), max LTV = 75% (7_500 bps)
        client.initialize(&admin, &2_000_000_i128, &7_500_u32);
        (env, admin, user, client)
    }

    /// Happy path: user deposits collateral, borrows within LTV, repays debt, and withdraws collateral.
    #[test]
    fn test_normal_deposit_borrow_repay_withdraw_works() {
        let (_env, _admin, user, client) = setup();

        // Deposit 1,000 collateral units ($2,000 USD value, 75% LTV -> max borrow = $1,500)
        client.deposit_collateral(&user, &1_000_i128);
        assert_eq!(client.get_collateral(&user), 1_000_i128);
        assert_eq!(client.get_max_borrow(&user), 1_500_i128);

        // Borrow $1,000
        client.borrow(&user, &1_000_i128);
        assert_eq!(client.get_debt(&user), 1_000_i128);

        // Repay full debt of $1,000
        let repaid = client.repay(&user, &1_000_i128);
        assert_eq!(repaid, 1_000_i128);
        assert_eq!(client.get_debt(&user), 0_i128);

        // Withdraw all 1,000 collateral units
        client.withdraw_collateral(&user, &1_000_i128);
        assert_eq!(client.get_collateral(&user), 0_i128);
    }

    /// ❌ Demonstrates vulnerability: user borrows $1,500 against 1,000 collateral ($2,000 value),
    /// then withdraws 100% of collateral without repaying debt.
    /// The vulnerable contract allows this, leaving $1,500 unbacked bad debt.
    #[test]
    fn test_vulnerable_collateral_drain_leaves_unbacked_bad_debt() {
        let (_env, _admin, user, client) = setup();

        // 1. Deposit 1,000 collateral units ($2,000 USD value)
        client.deposit_collateral(&user, &1_000_i128);

        // 2. Borrow maximum allowable debt ($1,500 USD)
        client.borrow(&user, &1_500_i128);
        assert_eq!(client.get_debt(&user), 1_500_i128);

        // 3. ❌ Withdraw all 1,000 collateral units without repaying
        client.withdraw_collateral(&user, &1_000_i128);

        // 4. Attacker now holds $1,500 borrowed funds while the contract has 0 collateral backing it!
        assert_eq!(client.get_collateral(&user), 0_i128);
        assert_eq!(client.get_debt(&user), 1_500_i128);
    }

    /// Boundary test: attempting to withdraw more collateral than deposited fails.
    #[test]
    #[should_panic(expected = "insufficient collateral balance")]
    fn test_vulnerable_cannot_withdraw_more_than_deposited() {
        let (_env, _admin, user, client) = setup();
        client.deposit_collateral(&user, &1_000_i128);
        client.withdraw_collateral(&user, &1_001_i128);
    }

    // ── secure mirror tests ───────────────────────────────────────────────────

    fn setup_secure() -> (
        Env,
        Address,
        Address,
        secure::SecureCollateralLendingPoolClient<'static>,
    ) {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let user = Address::generate(&env);
        let id = env.register_contract(None, secure::SecureCollateralLendingPool);
        let client = secure::SecureCollateralLendingPoolClient::new(&env, &id);

        client.initialize(&admin, &2_000_000_i128, &7_500_u32);
        (env, admin, user, client)
    }

    /// ✅ Secure path: blocks full withdrawal when outstanding debt exists.
    #[test]
    #[should_panic(expected = "health check failed: remaining collateral cannot cover debt")]
    fn test_secure_blocks_undercollateralized_withdrawal() {
        let (_env, _admin, user, client) = setup_secure();

        client.deposit_collateral(&user, &1_000_i128);
        client.borrow(&user, &1_500_i128);

        // ✅ SECURE: rejects withdrawal because remaining collateral (0) cannot support $1,500 debt
        client.withdraw_collateral(&user, &1_000_i128);
    }

    /// ✅ Secure path: allows partial withdrawal as long as remaining collateral covers debt.
    #[test]
    fn test_secure_allows_partial_safe_withdrawal() {
        let (_env, _admin, user, client) = setup_secure();

        // 1,000 collateral ($2,000 value, $1,500 max borrow)
        client.deposit_collateral(&user, &1_000_i128);

        // Borrow $750 (only requires $1,000 value = 500 collateral units at 75% LTV)
        client.borrow(&user, &750_i128);

        // Withdraw 500 collateral units (leaves 500 units = $1,000 value = $750 max borrow capacity)
        client.withdraw_collateral(&user, &500_i128);
        assert_eq!(client.get_collateral(&user), 500_i128);
        assert_eq!(client.get_debt(&user), 750_i128);
    }

    /// ✅ Secure path: boundary test — withdrawing 1 unit beyond safe threshold fails health check.
    #[test]
    #[should_panic(expected = "health check failed: remaining collateral cannot cover debt")]
    fn test_secure_boundary_one_unit_over_safe_limit_rejected() {
        let (_env, _admin, user, client) = setup_secure();

        client.deposit_collateral(&user, &1_000_i128);
        client.borrow(&user, &750_i128);

        // Withdrawing 501 units leaves 499 units ($998 value -> max borrow = $748.50 < $750 debt)
        client.withdraw_collateral(&user, &501_i128);
    }
}
