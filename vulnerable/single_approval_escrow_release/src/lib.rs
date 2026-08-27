//! VULNERABLE: Multisig Escrow with Hardcoded Approval Threshold
//!
//! A marketplace escrow where a buyer deposits funds for a seller, and
//! release of those funds is meant to require a configurable threshold of
//! independent arbiters to approve (e.g. 2-of-3), so that no single arbiter
//! can unilaterally move the buyer's escrowed funds. This is a standard
//! anti-collusion / anti-single-point-of-failure design used to protect
//! high-value escrows from a single compromised, bribed, or malicious
//! arbiter.
//!
//! `initialize` correctly validates that `threshold >= 1` and
//! `threshold <= arbiters.len()`, and `approve_release` correctly records
//! each arbiter's approval exactly once. The configured threshold is
//! stored and can be read back faithfully via `get_threshold`. Everything
//! about the *configuration* of the multisig is implemented correctly.
//!
//! VULNERABILITY: `release()` does not compare the number of collected
//! approvals against the configured `Threshold`. Instead it checks
//! `Approvals.len() < 1` — a hardcoded constant left over from what looks
//! like an earlier, single-approver draft of the contract that was never
//! updated when multisig support was added. Because the check only
//! requires *at least one* approval, an escrow explicitly configured to
//! require e.g. 2-of-3 (or any N > 1) arbiter consensus can actually be
//! released after a single arbiter approves.
//!
//! Impact: a single compromised, bribed, or malicious arbiter can
//! unilaterally move the buyer's escrowed funds to the seller, completely
//! defeating the purpose of the multisig configuration. The buyer receives
//! none of the protection they believed they were getting by requiring
//! multiple independent arbiters to agree.
//!
//! SEVERITY: Critical

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, token, Address, Env, Vec};

#[contracttype]
pub enum DataKey {
    Buyer,
    Seller,
    Token,
    Amount,
    Arbiters,
    Threshold,
    Approvals,
    Released,
}

#[contract]
pub struct MultisigEscrow;

#[contractimpl]
impl MultisigEscrow {
    /// Initialise the escrow. The buyer deposits `amount` of `token` into
    /// the contract now; releasing it to the seller later is meant to
    /// require `threshold` of the listed `arbiters` to approve.
    ///
    /// Panics if already initialized, or if `threshold` is not between 1
    /// and `arbiters.len()` inclusive.
    pub fn initialize(
        env: Env,
        buyer: Address,
        seller: Address,
        token: Address,
        amount: i128,
        arbiters: Vec<Address>,
        threshold: u32,
    ) {
        buyer.require_auth();
        assert!(
            !env.storage().persistent().has(&DataKey::Buyer),
            "already initialized"
        );

        // Threshold sanity check is present and correct: the developer
        // clearly understood the concept of an N-of-M threshold here.
        if threshold < 1 || threshold > arbiters.len() {
            panic!("invalid threshold");
        }

        token::Client::new(&env, &token).transfer(&buyer, &env.current_contract_address(), &amount);

        env.storage().persistent().set(&DataKey::Buyer, &buyer);
        env.storage().persistent().set(&DataKey::Seller, &seller);
        env.storage().persistent().set(&DataKey::Token, &token);
        env.storage().persistent().set(&DataKey::Amount, &amount);
        env.storage()
            .persistent()
            .set(&DataKey::Arbiters, &arbiters);
        env.storage()
            .persistent()
            .set(&DataKey::Threshold, &threshold);
        env.storage()
            .persistent()
            .set(&DataKey::Approvals, &Vec::<Address>::new(&env));
        env.storage().persistent().set(&DataKey::Released, &false);
    }

    /// Record `arbiter`'s approval to release the escrow. Only addresses
    /// listed in `Arbiters` may approve, and approving twice does not
    /// count twice.
    pub fn approve_release(env: Env, arbiter: Address) {
        arbiter.require_auth();

        let arbiters: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Arbiters)
            .expect("not initialized");
        if !arbiters.contains(&arbiter) {
            panic!("not an arbiter");
        }

        let released: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Released)
            .unwrap_or(false);
        if released {
            panic!("already released");
        }

        let mut approvals: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Approvals)
            .unwrap_or_else(|| Vec::new(&env));
        if !approvals.contains(&arbiter) {
            approvals.push_back(arbiter.clone());
        }
        env.storage()
            .persistent()
            .set(&DataKey::Approvals, &approvals);

        env.events().publish((symbol_short!("approve"),), arbiter);
    }

    /// Release the escrowed funds to the seller, provided enough arbiters
    /// have approved.
    ///
    /// # Vulnerability
    /// This compares the approval count against the hardcoded constant `1`
    /// instead of the configured `Threshold`, so a single arbiter approval
    /// is always sufficient regardless of how the escrow was configured.
    pub fn release(env: Env) {
        let released: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Released)
            .unwrap_or(false);
        if released {
            panic!("already released");
        }

        let approvals: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Approvals)
            .unwrap_or_else(|| Vec::new(&env));

        // ❌ VULNERABLE: should compare against the stored `Threshold`, not
        // a hardcoded `1`. This is leftover logic from an earlier
        // single-approver draft that was never updated when N-of-M
        // multisig support was added.
        if approvals.len() < 1 {
            panic!("insufficient approvals");
        }

        let seller: Address = env.storage().persistent().get(&DataKey::Seller).unwrap();
        let token_id: Address = env.storage().persistent().get(&DataKey::Token).unwrap();
        let amount: i128 = env.storage().persistent().get(&DataKey::Amount).unwrap();

        token::Client::new(&env, &token_id).transfer(
            &env.current_contract_address(),
            &seller,
            &amount,
        );

        env.storage().persistent().set(&DataKey::Released, &true);
        env.events()
            .publish((symbol_short!("released"),), (seller, amount));
    }

    /// Number of distinct arbiters who have approved release so far.
    pub fn approval_count(env: Env) -> u32 {
        let approvals: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Approvals)
            .unwrap_or_else(|| Vec::new(&env));
        approvals.len()
    }

    /// The configured N-of-M approval threshold.
    pub fn get_threshold(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::Threshold)
            .expect("not initialized")
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

    const DEPOSIT_AMOUNT: i128 = 1_000;

    fn setup() -> (
        Env,
        MultisigEscrowClient<'static>,
        Address,      // token id
        Address,      // buyer
        Address,      // seller
        Vec<Address>, // arbiters (3)
    ) {
        let env = Env::default();
        env.mock_all_auths();

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let arbiter_1 = Address::generate(&env);
        let arbiter_2 = Address::generate(&env);
        let arbiter_3 = Address::generate(&env);

        let token_admin = Address::generate(&env);
        let token_id = env
            .register_stellar_asset_contract_v2(token_admin.clone())
            .address();
        StellarAssetClient::new(&env, &token_id).mint(&buyer, &DEPOSIT_AMOUNT);

        let mut arbiters = Vec::new(&env);
        arbiters.push_back(arbiter_1);
        arbiters.push_back(arbiter_2);
        arbiters.push_back(arbiter_3);

        let contract_id = env.register_contract(None, MultisigEscrow);
        let client = MultisigEscrowClient::new(&env, &contract_id);
        client.initialize(
            &buyer,
            &seller,
            &token_id,
            &DEPOSIT_AMOUNT,
            &arbiters,
            &2u32,
        );

        (env, client, token_id, buyer, seller, arbiters)
    }

    /// Sanity check: the configured threshold is stored and read back
    /// faithfully. This isolates the bug to the comparison inside
    /// `release()` rather than the configuration/storage layer.
    #[test]
    fn test_threshold_value_is_stored_correctly() {
        let (_env, client, ..) = setup();
        assert_eq!(client.get_threshold(), 2);
    }

    /// The exploit: even though this escrow was configured to require 2-of-3
    /// arbiter approvals, a single arbiter approving is enough to release
    /// the full escrowed amount to the seller.
    #[test]
    fn test_single_arbiter_releases_escrow_despite_two_of_three_threshold_bug() {
        let (env, client, token_id, _buyer, seller, arbiters) = setup();
        let token = TokenClient::new(&env, &token_id);

        let only_arbiter = arbiters.get(0).unwrap();
        client.approve_release(&only_arbiter);

        assert_eq!(client.approval_count(), 1);
        assert_eq!(client.get_threshold(), 2);
        assert!(client.approval_count() < client.get_threshold());

        client.release();

        assert_eq!(token.balance(&seller), DEPOSIT_AMOUNT);
    }

    /// Control: with zero approvals, release() still panics, since the
    /// hardcoded check is `< 1`, not `< 0`. This shows the bug only
    /// manifests once the trivially-low bar of exactly one approval is
    /// cleared, not that release() is unconditionally open.
    #[test]
    #[should_panic(expected = "insufficient approvals")]
    fn test_no_approvals_still_blocks_release() {
        let (_env, client, ..) = setup();
        client.release();
    }
}
