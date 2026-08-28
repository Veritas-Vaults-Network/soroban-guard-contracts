//! VULNERABLE: Airdrop Expiry Ignored
//!
//! An expiring Merkle airdrop that is documented to close at `end_time`,
//! after which the admin sweeps any unclaimed balance back to a treasury
//! address — a standard, realistic pattern so leftover allocations don't
//! stay stranded in the contract forever.
//!
//! VULNERABILITY: `claim()` never checks `end_time` at all. `sweep_unclaimed()`
//! correctly gates on `env.ledger().timestamp() > end_time`, but nothing stops
//! `claim()` from succeeding at any time before *or* long after the advertised
//! close date.
//!
//! SEVERITY: Medium
//!
//! Impact:
//! (a) The campaign's advertised close date is meaningless — claims work
//!     forever, breaking any planning or accounting that assumes the campaign
//!     actually closes at `end_time`.
//! (b) If the admin sweeps "unclaimed" funds to the treasury after `end_time`
//!     believing the campaign is over, a late but legitimately-eligible
//!     claimant can still call `claim()` afterward. If the sweep took
//!     everything, the token transfer panics on insufficient contract
//!     balance — a confusing, unexpected failure for someone who should have
//!     been paid. If the admin only swept part of the balance (or funded the
//!     contract again for another purpose), a late claim can succeed anyway,
//!     improperly drawing down funds the admin already re-allocated
//!     elsewhere.

#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, xdr::ToXdr, Address, Bytes, BytesN,
    Env, Vec,
};

#[contracttype]
pub enum DataKey {
    Admin,
    Token,
    MerkleRoot,
    EndTime,
    Treasury,
    Claimed(Address),
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn leaf_hash(env: &Env, claimant: &Address, amount: i128) -> BytesN<32> {
    let mut data = Bytes::new(env);
    data.append(&claimant.to_xdr(env));
    data.extend_from_array(&amount.to_be_bytes());
    env.crypto().sha256(&data).into()
}

/// Hash two 32-byte nodes together, smaller first (canonical ordering).
fn hash_pair(env: &Env, a: &BytesN<32>, b: &BytesN<32>) -> BytesN<32> {
    let mut data = Bytes::new(env);
    if a <= b {
        data.append(&Bytes::from(a.clone()));
        data.append(&Bytes::from(b.clone()));
    } else {
        data.append(&Bytes::from(b.clone()));
        data.append(&Bytes::from(a.clone()));
    }
    env.crypto().sha256(&data).into()
}

fn verify_merkle_proof(env: &Env, claimant: &Address, amount: i128, proof: &Vec<BytesN<32>>) {
    let root: BytesN<32> = env
        .storage()
        .persistent()
        .get(&DataKey::MerkleRoot)
        .expect("not initialized");

    let mut node = leaf_hash(env, claimant, amount);
    for sibling in proof.iter() {
        node = hash_pair(env, &node, &sibling);
    }
    assert!(node == root, "invalid merkle proof");
}

fn is_claimed(env: &Env, claimant: &Address) -> bool {
    env.storage()
        .persistent()
        .get(&DataKey::Claimed(claimant.clone()))
        .unwrap_or(false)
}

fn mark_claimed(env: &Env, claimant: &Address) {
    env.storage()
        .persistent()
        .set(&DataKey::Claimed(claimant.clone()), &true);
}

// ── contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct ExpiringAirdrop;

#[contractimpl]
impl ExpiringAirdrop {
    pub fn initialize(
        env: Env,
        admin: Address,
        token: Address,
        merkle_root: BytesN<32>,
        end_time: u64,
        treasury: Address,
    ) {
        admin.require_auth();
        assert!(
            !env.storage().persistent().has(&DataKey::Admin),
            "already initialized"
        );
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Token, &token);
        env.storage()
            .persistent()
            .set(&DataKey::MerkleRoot, &merkle_root);
        env.storage().persistent().set(&DataKey::EndTime, &end_time);
        env.storage()
            .persistent()
            .set(&DataKey::Treasury, &treasury);
    }

    /// Admin deposits tokens into the airdrop pool.
    pub fn fund(env: Env, amount: i128) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        let token: Address = env.storage().persistent().get(&DataKey::Token).unwrap();
        token::Client::new(&env, &token).transfer(&admin, &env.current_contract_address(), &amount);

        env.events()
            .publish((symbol_short!("fund"),), (admin, amount));
    }

    /// VULNERABLE: claim never checks whether the airdrop has expired.
    /// The campaign is documented to close at `end_time`, but this function
    /// happily accepts valid proofs forever, including long after the
    /// advertised close date — and even after `sweep_unclaimed()` has moved
    /// the pool's balance to the treasury.
    ///
    /// # Vulnerability
    /// Missing `assert!(env.ledger().timestamp() <= end_time, ...)` check.
    /// Impact: the airdrop never actually closes, and late claims can panic
    /// unexpectedly (post-sweep) or improperly draw down re-allocated funds.
    pub fn claim(env: Env, claimant: Address, amount: i128, proof: Vec<BytesN<32>>) {
        claimant.require_auth();
        assert!(!is_claimed(&env, &claimant), "already claimed");

        // ❌ VULNERABLE: no check against DataKey::EndTime here at all.

        verify_merkle_proof(&env, &claimant, amount, &proof);

        // ✅ Mark claimed BEFORE transfer (checks-effects-interactions)
        mark_claimed(&env, &claimant);

        let token: Address = env.storage().persistent().get(&DataKey::Token).unwrap();
        token::Client::new(&env, &token).transfer(
            &env.current_contract_address(),
            &claimant,
            &amount,
        );

        env.events()
            .publish((symbol_short!("claim"),), (claimant, amount));
    }

    /// Admin-only: after the airdrop has genuinely closed, sweep whatever is
    /// left in the pool back to the treasury. Correctly gated on `end_time`
    /// — it is `claim()` that is missing the equivalent check.
    pub fn sweep_unclaimed(env: Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        let end_time: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::EndTime)
            .expect("not initialized");
        assert!(env.ledger().timestamp() > end_time, "airdrop still active");

        let token: Address = env.storage().persistent().get(&DataKey::Token).unwrap();
        let treasury: Address = env.storage().persistent().get(&DataKey::Treasury).unwrap();

        let token_client = token::Client::new(&env, &token);
        let balance = token_client.balance(&env.current_contract_address());
        token_client.transfer(&env.current_contract_address(), &treasury, &balance);

        env.events()
            .publish((symbol_short!("sweep"),), (treasury, balance));
    }

    pub fn get_claimed(env: Env, address: Address) -> bool {
        is_claimed(&env, &address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        token::{Client as TokenClient, StellarAssetClient},
        Address, BytesN, Env, Vec,
    };

    const END_TIME: u64 = 1_000_000;

    /// Build a two-leaf Merkle tree for `claimant` and return (root, proof).
    /// Tree:
    ///   leaf0 = hash(claimant, amount)
    ///   leaf1 = hash(other, 0)          ← dummy second leaf
    ///   root  = hash_pair(leaf0, leaf1)
    fn build_tree(
        env: &Env,
        claimant: &Address,
        amount: i128,
        other: &Address,
    ) -> (BytesN<32>, Vec<BytesN<32>>) {
        let leaf0 = leaf_hash(env, claimant, amount);
        let leaf1 = leaf_hash(env, other, 0i128);
        let root = hash_pair(env, &leaf0, &leaf1);
        let mut proof = Vec::new(env);
        proof.push_back(leaf1);
        (root, proof)
    }

    struct TestCtx {
        env: Env,
        token_id: Address,
        admin: Address,
        claimant: Address,
        other: Address,
        treasury: Address,
    }

    fn setup() -> TestCtx {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().with_mut(|l| l.timestamp = 0);

        let admin = Address::generate(&env);
        let claimant = Address::generate(&env);
        let other = Address::generate(&env);
        let treasury = Address::generate(&env);

        let token_admin = Address::generate(&env);
        let token_id = env
            .register_stellar_asset_contract_v2(token_admin.clone())
            .address();

        StellarAssetClient::new(&env, &token_id).mint(&admin, &1_000_000);

        TestCtx {
            env,
            token_id,
            admin,
            claimant,
            other,
            treasury,
        }
    }

    /// Demonstrates the core bug: claim() succeeds no matter how far past
    /// end_time the ledger clock is, because expiry is never checked there.
    #[test]
    fn test_claim_succeeds_long_after_advertised_expiry_bug() {
        let ctx = setup();
        let amount = 500i128;

        let (root, proof) = build_tree(&ctx.env, &ctx.claimant, amount, &ctx.other);

        let contract_id = ctx.env.register_contract(None, ExpiringAirdrop);
        let client = ExpiringAirdropClient::new(&ctx.env, &contract_id);

        client.initialize(&ctx.admin, &ctx.token_id, &root, &END_TIME, &ctx.treasury);
        client.fund(&amount);

        // Advance well past the advertised close date.
        ctx.env
            .ledger()
            .with_mut(|l| l.timestamp = END_TIME + 10_000_000);

        // ❌ VULNERABLE: claim still succeeds long after end_time.
        client.claim(&ctx.claimant, &amount, &proof);
        assert!(client.get_claimed(&ctx.claimant));
        assert_eq!(
            TokenClient::new(&ctx.env, &ctx.token_id).balance(&ctx.claimant),
            amount
        );
    }

    /// Control: sweep_unclaimed() correctly reverts before end_time, proving
    /// only the claim() path is missing the equivalent expiry check.
    #[test]
    #[should_panic(expected = "airdrop still active")]
    fn test_control_sweep_before_expiry_reverts() {
        let ctx = setup();
        let amount = 500i128;

        let (root, _proof) = build_tree(&ctx.env, &ctx.claimant, amount, &ctx.other);

        let contract_id = ctx.env.register_contract(None, ExpiringAirdrop);
        let client = ExpiringAirdropClient::new(&ctx.env, &contract_id);

        client.initialize(&ctx.admin, &ctx.token_id, &root, &END_TIME, &ctx.treasury);
        client.fund(&amount);

        // Still well before end_time.
        ctx.env.ledger().with_mut(|l| l.timestamp = END_TIME - 1);

        client.sweep_unclaimed();
    }

    /// Demonstrates the double-booking hazard: admin sweeps believing the
    /// campaign is over, but a late (still-eligible) claimant then triggers
    /// a confusing panic instead of a clean "airdrop expired" rejection.
    #[test]
    #[should_panic]
    fn test_late_claim_after_sweep_panics_on_insufficient_balance() {
        let ctx = setup();
        let amount = 500i128;

        let (root, proof) = build_tree(&ctx.env, &ctx.claimant, amount, &ctx.other);

        let contract_id = ctx.env.register_contract(None, ExpiringAirdrop);
        let client = ExpiringAirdropClient::new(&ctx.env, &contract_id);

        client.initialize(&ctx.admin, &ctx.token_id, &root, &END_TIME, &ctx.treasury);
        // Fund with exactly `amount` so the sweep drains the pool to zero.
        client.fund(&amount);

        // Past end_time: admin sweeps the (believed-unclaimed) pool.
        ctx.env.ledger().with_mut(|l| l.timestamp = END_TIME + 1);
        client.sweep_unclaimed();
        assert_eq!(
            TokenClient::new(&ctx.env, &ctx.token_id).balance(&ctx.treasury),
            amount
        );

        // The late but legitimately-eligible claimant shows up afterward.
        // claim() still has no expiry check, so it proceeds past all its own
        // guards and only fails when the token contract can't cover the
        // transfer — a confusing panic instead of a clean rejection.
        client.claim(&ctx.claimant, &amount, &proof);
    }
}
