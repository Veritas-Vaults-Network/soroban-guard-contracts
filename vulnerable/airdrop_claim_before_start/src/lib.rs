//! VULNERABLE: Missing Start-Time Check in Time-Gated Merkle Airdrop
//!
//! A merkle airdrop is meant to be claimable only during a public window
//! `[start_time, end_time]` (unix timestamps, `env.ledger().timestamp()`).
//! The window exists so that insiders or bots who learn the merkle root (or
//! their own leaf data) ahead of the official public announcement cannot
//! front-run the "fair launch" — e.g. claiming and dumping tokens before
//! liquidity/price discovery has even been set up for everyone else.
//!
//! VULNERABILITY: `claim()` only asserts `env.ledger().timestamp() <=
//! end_time` — it never checks `env.ledger().timestamp() >= start_time`.
//! `start_time` is stored at `initialize()` time and displayed/relied upon
//! everywhere else, but the actual gate protecting it from being used early
//! simply does not exist. Because the merkle root (and therefore every
//! leaf's address/amount pair) must be computed and published *before* the
//! announced public start in order for proofs to be generated and
//! distributed, anyone with early access to that data — a team insider, a
//! leaked snapshot, or a bot that scrapes the pending root from a
//! not-yet-announced contract — can call `claim()` the moment the contract
//! is funded, arbitrarily long before the advertised start_time. This
//! defeats the entire purpose of a scheduled, fair public launch and lets
//! early claimants sell/act on their allocation before the rest of the
//! eligible set even has the ability to claim.
//!
//! SEVERITY: Medium

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
    StartTime,
    EndTime,
    Claimed(Address),
}

#[contract]
pub struct TimedAirdrop;

// ── helpers ──────────────────────────────────────────────────────────────────

/// leaf = sha256(claimant.to_xdr() || amount.to_be_bytes())
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

#[contractimpl]
impl TimedAirdrop {
    pub fn initialize(
        env: Env,
        admin: Address,
        token: Address,
        merkle_root: BytesN<32>,
        start_time: u64,
        end_time: u64,
    ) {
        admin.require_auth();
        assert!(
            !env.storage().persistent().has(&DataKey::Admin),
            "already initialized"
        );
        assert!(start_time < end_time, "start_time must be before end_time");

        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Token, &token);
        env.storage()
            .persistent()
            .set(&DataKey::MerkleRoot, &merkle_root);
        env.storage()
            .persistent()
            .set(&DataKey::StartTime, &start_time);
        env.storage().persistent().set(&DataKey::EndTime, &end_time);
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

    /// VULNERABLE: only the end of the claim window is enforced.
    ///
    /// # Vulnerability
    /// Missing `env.ledger().timestamp() >= start_time` check. Impact: anyone
    /// with early knowledge of the merkle root/leaf data can claim (and act
    /// on) their allocation long before the officially announced public
    /// start, defeating the fair-launch guarantee the start_time was meant
    /// to provide.
    pub fn claim(env: Env, claimant: Address, amount: i128, proof: Vec<BytesN<32>>) {
        claimant.require_auth();
        assert!(!is_claimed(&env, &claimant), "already claimed");

        let end_time: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::EndTime)
            .expect("not initialized");

        // ❌ VULNERABLE: start_time is stored but never checked here.
        // let start_time: u64 = env.storage().persistent().get(&DataKey::StartTime).unwrap();
        // assert!(env.ledger().timestamp() >= start_time, "airdrop has not started");
        assert!(env.ledger().timestamp() <= end_time, "airdrop has ended");

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

    /// Build a two-leaf Merkle tree for `claimant` and return (root, proof).
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

    fn setup() -> (Env, Address, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let claimant = Address::generate(&env);
        let other = Address::generate(&env);

        let token_admin = Address::generate(&env);
        let token_id = env
            .register_stellar_asset_contract_v2(token_admin.clone())
            .address();

        StellarAssetClient::new(&env, &token_id).mint(&admin, &10_000);

        (env, token_id, admin, claimant, other)
    }

    /// Demonstrates the bug: claiming succeeds well before the announced
    /// public start_time, because claim() never checks the lower bound.
    #[test]
    fn test_claim_before_announced_start_succeeds_bug() {
        let (env, token_id, admin, claimant, other) = setup();
        let amount = 500i128;

        let (root, proof) = build_tree(&env, &claimant, amount, &other);

        let now = env.ledger().timestamp();
        let start_time = now + 100_000;
        let end_time = start_time + 100_000;

        let contract_id = env.register_contract(None, TimedAirdrop);
        let client = TimedAirdropClient::new(&env, &contract_id);

        client.initialize(&admin, &token_id, &root, &start_time, &end_time);
        client.fund(&amount);

        // Current ledger timestamp is still `now`, far before `start_time`.
        assert!(env.ledger().timestamp() < start_time);

        // ❌ BUG: this succeeds even though the public window hasn't opened yet.
        client.claim(&claimant, &amount, &proof);
        assert!(client.get_claimed(&claimant));
        assert_eq!(TokenClient::new(&env, &token_id).balance(&claimant), amount);
    }

    /// Control: the end_time check does work correctly.
    #[test]
    #[should_panic(expected = "airdrop has ended")]
    fn test_control_claim_after_end_time_reverts() {
        let (env, token_id, admin, claimant, other) = setup();
        let amount = 500i128;

        let (root, proof) = build_tree(&env, &claimant, amount, &other);

        let now = env.ledger().timestamp();
        let start_time = now + 1_000;
        let end_time = start_time + 1_000;

        let contract_id = env.register_contract(None, TimedAirdrop);
        let client = TimedAirdropClient::new(&env, &contract_id);

        client.initialize(&admin, &token_id, &root, &start_time, &end_time);
        client.fund(&amount);

        env.ledger().with_mut(|l| {
            l.timestamp = end_time + 1;
        });

        client.claim(&claimant, &amount, &proof);
    }

    /// Control: a normal claim within the announced window succeeds.
    #[test]
    fn test_control_claim_within_window_succeeds() {
        let (env, token_id, admin, claimant, other) = setup();
        let amount = 500i128;

        let (root, proof) = build_tree(&env, &claimant, amount, &other);

        let now = env.ledger().timestamp();
        let start_time = now + 1_000;
        let end_time = start_time + 1_000;

        let contract_id = env.register_contract(None, TimedAirdrop);
        let client = TimedAirdropClient::new(&env, &contract_id);

        client.initialize(&admin, &token_id, &root, &start_time, &end_time);
        client.fund(&amount);

        env.ledger().with_mut(|l| {
            l.timestamp = start_time + 500;
        });

        client.claim(&claimant, &amount, &proof);
        assert!(client.get_claimed(&claimant));
        assert_eq!(TokenClient::new(&env, &token_id).balance(&claimant), amount);
    }
}
