//! VULNERABLE: English Auction with Broken Pull-Payment Refund
//!
//! An English auction where bidders escrow tokens with each `bid()` call.
//! Following the standard pull-payment pattern (never push tokens to an
//! outbid bidder from inside `bid()`, since that transfer could fail or be
//! used to reenter), an outbid bidder is expected to reclaim their escrowed
//! tokens later via a separate `withdraw()` call.
//!
//! VULNERABILITY: the contract tracks only a **single** pending-return slot
//! (`PendingReturnBidder` / `PendingReturnAmount`), meant to record "the most
//! recently outbid bidder", instead of a per-bidder mapping (e.g.
//! `PendingReturn(Address) -> i128`). Every time a new highest bid comes in,
//! `bid()` unconditionally overwrites that single slot with the *previous*
//! highest bidder's refund — clobbering whatever was there before, even if
//! that prior entry was never claimed.
//!
//! Concretely: bidder A bids, is outbid by B (A's refund is now recorded).
//! Before A calls `withdraw()`, C outbids B. The slot is overwritten with
//! B's refund, and A's entry is gone forever. The tokens A escrowed are
//! still sitting in the contract, but there is no code path — not even for
//! the admin — that can ever return them to A. This mirrors a well-known
//! historical bug in the original "SimpleAuction" Solidity tutorial
//! contract, ported here to Soroban.
//!
//! SEVERITY: High

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    Token,
    EndTime,
    Seller,
    HighestBidder,
    HighestBid,
    PendingReturnBidder,
    PendingReturnAmount,
}

#[contract]
pub struct EnglishAuction;

#[contractimpl]
impl EnglishAuction {
    /// Initialise the auction. Panics if already initialized.
    pub fn initialize(env: Env, admin: Address, seller: Address, token: Address, end_time: u64) {
        admin.require_auth();
        assert!(
            !env.storage().persistent().has(&DataKey::Admin),
            "already initialized"
        );

        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Seller, &seller);
        env.storage().persistent().set(&DataKey::Token, &token);
        env.storage().persistent().set(&DataKey::EndTime, &end_time);
        env.storage().persistent().set(&DataKey::HighestBid, &0i128);
    }

    /// Place a bid. The bidder's tokens are escrowed into the contract
    /// immediately. If this bid outbids a previous highest bidder, that
    /// bidder becomes eligible to `withdraw()` their escrowed tokens.
    ///
    /// # Vulnerability
    /// The outbid bidder's refund is recorded in a single shared
    /// `PendingReturnBidder` / `PendingReturnAmount` slot rather than a
    /// per-bidder map. If a second outbid happens before the first outbid
    /// bidder withdraws, their pending refund is silently overwritten and
    /// their escrowed tokens become permanently stuck in the contract.
    pub fn bid(env: Env, bidder: Address, amount: i128) {
        bidder.require_auth();

        let end_time: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::EndTime)
            .expect("not initialized");
        if env.ledger().timestamp() >= end_time {
            panic!("auction ended");
        }

        let highest_bid: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::HighestBid)
            .unwrap_or(0);
        if amount <= highest_bid {
            panic!("bid too low");
        }

        let token_id: Address = env.storage().persistent().get(&DataKey::Token).unwrap();
        token::Client::new(&env, &token_id).transfer(
            &bidder,
            &env.current_contract_address(),
            &amount,
        );

        // If there is already a highest bidder, they are now outbid and
        // must be able to reclaim their escrowed tokens.
        let prev_bidder: Option<Address> = env.storage().persistent().get(&DataKey::HighestBidder);
        if let Some(prev_bidder) = prev_bidder {
            // ❌ VULNERABLE: this single shared slot is overwritten on every
            // outbid, regardless of whether the previous occupant ever
            // claimed their refund. It should instead be a per-address
            // mapping, e.g. `PendingReturn(Address) -> i128`, so that every
            // outbid bidder independently keeps their own claimable amount.
            env.storage()
                .persistent()
                .set(&DataKey::PendingReturnBidder, &prev_bidder);
            env.storage()
                .persistent()
                .set(&DataKey::PendingReturnAmount, &highest_bid);
        }

        env.storage()
            .persistent()
            .set(&DataKey::HighestBidder, &bidder);
        env.storage()
            .persistent()
            .set(&DataKey::HighestBid, &amount);
    }

    /// Withdraw an outstanding pending return. Only works if `caller` is
    /// exactly the address currently recorded in the (single) pending
    /// return slot. Clears the slot by zeroing the amount, so a repeat call
    /// also fails with "nothing to withdraw".
    pub fn withdraw(env: Env, caller: Address) {
        caller.require_auth();

        let pending_bidder: Option<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::PendingReturnBidder);
        let pending_amount: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::PendingReturnAmount)
            .unwrap_or(0);

        let is_eligible = matches!(pending_bidder, Some(b) if b == caller) && pending_amount > 0;
        if !is_eligible {
            panic!("nothing to withdraw");
        }

        // Clear the slot before transferring (checks-effects-interactions).
        env.storage()
            .persistent()
            .set(&DataKey::PendingReturnAmount, &0i128);

        let token_id: Address = env.storage().persistent().get(&DataKey::Token).unwrap();
        token::Client::new(&env, &token_id).transfer(
            &env.current_contract_address(),
            &caller,
            &pending_amount,
        );
    }

    /// Admin-only: after the auction ends, pay out the highest bid to the seller.
    pub fn end_auction(env: Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        let end_time: u64 = env.storage().persistent().get(&DataKey::EndTime).unwrap();
        if env.ledger().timestamp() < end_time {
            panic!("auction not ended");
        }

        let seller: Address = env.storage().persistent().get(&DataKey::Seller).unwrap();
        let highest_bid: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::HighestBid)
            .unwrap_or(0);
        let token_id: Address = env.storage().persistent().get(&DataKey::Token).unwrap();
        token::Client::new(&env, &token_id).transfer(
            &env.current_contract_address(),
            &seller,
            &highest_bid,
        );
    }

    pub fn highest_bid(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::HighestBid)
            .unwrap_or(0)
    }

    pub fn highest_bidder(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::HighestBidder)
            .expect("no bids yet")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        token::{Client as TokenClient, StellarAssetClient},
        Address, Env,
    };

    const END_TIME: u64 = 1_000_000;
    const MINT_AMOUNT: i128 = 1_000;

    fn setup() -> (
        Env,
        EnglishAuctionClient<'static>,
        Address, // contract id
        Address, // token id
        Address, // admin
        Address, // seller
        Address, // bidder A
        Address, // bidder B
        Address, // bidder C
    ) {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let seller = Address::generate(&env);
        let bidder_a = Address::generate(&env);
        let bidder_b = Address::generate(&env);
        let bidder_c = Address::generate(&env);

        let token_admin = Address::generate(&env);
        let token_id = env
            .register_stellar_asset_contract_v2(token_admin.clone())
            .address();
        let token_sac = StellarAssetClient::new(&env, &token_id);
        token_sac.mint(&bidder_a, &MINT_AMOUNT);
        token_sac.mint(&bidder_b, &MINT_AMOUNT);
        token_sac.mint(&bidder_c, &MINT_AMOUNT);

        let contract_id = env.register_contract(None, EnglishAuction);
        let client = EnglishAuctionClient::new(&env, &contract_id);
        client.initialize(&admin, &seller, &token_id, &END_TIME);

        (
            env,
            client,
            contract_id,
            token_id,
            admin,
            seller,
            bidder_a,
            bidder_b,
            bidder_c,
        )
    }

    /// Control case: exactly one outstanding refund exists at a time, and
    /// the outbid bidder successfully reclaims their escrowed tokens.
    #[test]
    fn test_control_single_outbid_withdraw_succeeds() {
        let (env, client, _contract_id, token_id, _admin, _seller, bidder_a, bidder_b, _bidder_c) =
            setup();
        let token = TokenClient::new(&env, &token_id);

        client.bid(&bidder_a, &100);
        client.bid(&bidder_b, &200);

        assert_eq!(token.balance(&bidder_a), MINT_AMOUNT - 100);

        client.withdraw(&bidder_a);

        // A's escrowed 100 came back in full.
        assert_eq!(token.balance(&bidder_a), MINT_AMOUNT);
    }

    /// The exploit: a second outbid before the first outbid bidder withdraws
    /// overwrites the single shared pending-return slot, permanently
    /// blocking that bidder's refund.
    #[test]
    #[should_panic(expected = "nothing to withdraw")]
    fn test_second_outbid_before_withdrawal_overwrites_and_blocks_refund() {
        let (_env, client, _contract_id, _token_id, _admin, _seller, bidder_a, bidder_b, bidder_c) =
            setup();

        client.bid(&bidder_a, &100); // A is highest
        client.bid(&bidder_b, &200); // A outbid; pending slot = (A, 100), unclaimed
        client.bid(&bidder_c, &300); // B outbid; pending slot overwritten to (B, 200)

        // A's refund entry no longer exists — this panics.
        client.withdraw(&bidder_a);
    }

    /// Companion (non-panicking) assertion: A's tokens are never returned
    /// and remain stuck inside the contract after the overwrite above.
    #[test]
    fn test_outbid_funds_permanently_stuck_in_contract() {
        let (env, client, contract_id, token_id, _admin, _seller, bidder_a, bidder_b, bidder_c) =
            setup();
        let token = TokenClient::new(&env, &token_id);

        client.bid(&bidder_a, &100);
        client.bid(&bidder_b, &200);
        client.bid(&bidder_c, &300);

        // A paid 100 into escrow and never got it back.
        assert_eq!(token.balance(&bidder_a), MINT_AMOUNT - 100);

        // All escrowed funds (A's 100 + B's 200 + C's 300 = 600) are still
        // sitting in the contract, including A's now-unrecoverable 100.
        assert_eq!(token.balance(&contract_id), 100 + 200 + 300);

        // There is no way left to reclaim A's share: the pending-return
        // slot now points at B, not A.
        env.as_contract(&contract_id, || {
            let pending_bidder: Option<Address> = env
                .storage()
                .persistent()
                .get(&DataKey::PendingReturnBidder);
            assert_eq!(pending_bidder, Some(bidder_b.clone()));
        });
    }

    #[test]
    #[should_panic(expected = "bid too low")]
    fn test_bid_must_exceed_current_highest() {
        let (_env, client, _contract_id, _token_id, _admin, _seller, bidder_a, bidder_b, _bidder_c) =
            setup();

        client.bid(&bidder_a, &200);
        client.bid(&bidder_b, &200);
    }

    #[test]
    #[should_panic(expected = "auction ended")]
    fn test_bid_after_end_time_panics() {
        let (env, client, _contract_id, _token_id, _admin, _seller, bidder_a, _bidder_b, _bidder_c) =
            setup();

        env.ledger().with_mut(|l| l.timestamp = END_TIME);
        client.bid(&bidder_a, &100);
    }

    #[test]
    fn test_end_auction_pays_seller() {
        let (env, client, _contract_id, token_id, _admin, seller, bidder_a, bidder_b, _bidder_c) =
            setup();
        let token = TokenClient::new(&env, &token_id);

        client.bid(&bidder_a, &100);
        client.bid(&bidder_b, &200);

        env.ledger().with_mut(|l| l.timestamp = END_TIME);
        client.end_auction();

        assert_eq!(token.balance(&seller), 200);
        assert_eq!(client.highest_bid(), 200);
        assert_eq!(client.highest_bidder(), bidder_b);
    }
}
