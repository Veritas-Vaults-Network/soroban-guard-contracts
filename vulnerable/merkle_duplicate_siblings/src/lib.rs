//! VULNERABLE: Merkle Duplicate Siblings (Proof-Content-Based Replay Protection)
//!
//! This is an incrementally-growing ("rolling") merkle airdrop chain: instead of
//! publishing one fixed merkle tree up front, the admin appends one new claimant
//! at a time as they become eligible (e.g. a referral-driven or KYC-gated airdrop
//! where people are approved on a rolling basis). Each append chains the root:
//!
//!   new_root = hash_pair(old_root, leaf_hash(new_claimant, new_amount))
//!
//! or just `leaf_hash(claimant, amount)` if this is the very first entry. This is
//! a real, legitimate incremental-merkle-chain pattern.
//!
//! VULNERABILITY: replay protection is keyed by `sha256(claimant || proof)`
//! (see `claim_fingerprint`) instead of by the claimant's address alone.
//!
//! SEVERITY: Critical
//!
//! Because the chain is built by simple, undeduplicated appends (`add_claimant`
//! never checks whether `claimant` has already been added), if the admin
//! accidentally — or maliciously — adds the same claimant a second time (a very
//! plausible operational slip, e.g. re-running a batch-approval script), that
//! claimant ends up with TWO structurally different, both cryptographically
//! valid, proofs to the same current root: one using the "short" path through
//! the newer top-level link created by the duplicate append, and one using the
//! "long" path that walks back through the original insertion point. Since each
//! distinct proof array produces a distinct fingerprint, the claimant can redeem
//! the SAME underlying allocation once per valid proof, draining more than they
//! were ever allocated.
//!
//! The fix is to key `Claimed` by claimant address alone, independent of which
//! proof was used to reach the root — see `Claimed(Address)` in the sibling
//! `secure_airdrop`/`merkle_leaf_missing_amount::secure` style contracts.

#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, xdr::ToXdr, Address, Bytes, BytesN,
    Env, Vec,
};

#[contracttype]
pub enum DataKey {
    Admin,
    Token,
    Root,
    Claimed(BytesN<32>),
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

// ❌ VULNERABLE: fingerprint binds replay-protection to the *entire proof
// array* rather than to the claimant alone. A claimant with two distinct valid
// proofs to the current root gets two distinct fingerprints, so both are
// independently claimable.
fn claim_fingerprint(env: &Env, claimant: &Address, proof: &Vec<BytesN<32>>) -> BytesN<32> {
    let mut buf = Bytes::new(env);
    buf.append(&claimant.to_xdr(env));
    for sibling in proof.iter() {
        buf.append(&Bytes::from(sibling.clone()));
    }
    env.crypto().sha256(&buf).into()
}

fn get_root(env: &Env) -> Option<BytesN<32>> {
    env.storage().persistent().get(&DataKey::Root)
}

fn is_claimed(env: &Env, fingerprint: &BytesN<32>) -> bool {
    env.storage()
        .persistent()
        .get(&DataKey::Claimed(fingerprint.clone()))
        .unwrap_or(false)
}

fn mark_claimed(env: &Env, fingerprint: &BytesN<32>) {
    env.storage()
        .persistent()
        .set(&DataKey::Claimed(fingerprint.clone()), &true);
}

// ── contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct RollingAirdrop;

#[contractimpl]
impl RollingAirdrop {
    pub fn initialize(env: Env, admin: Address, token: Address) {
        admin.require_auth();
        assert!(
            !env.storage().persistent().has(&DataKey::Admin),
            "already initialized"
        );
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Token, &token);
    }

    /// Admin appends a new claimant/amount to the rolling merkle chain.
    ///
    /// # Vulnerability (root cause)
    /// This never checks whether `claimant` has already been added before, at
    /// any amount. Appending the same claimant twice gives them two valid
    /// proofs against the resulting root — see module docs for the exploit.
    pub fn add_claimant(env: Env, claimant: Address, amount: i128) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        let new_leaf = leaf_hash(&env, &claimant, amount);
        let new_root = match get_root(&env) {
            Some(old_root) => hash_pair(&env, &old_root, &new_leaf),
            None => new_leaf,
        };
        env.storage().persistent().set(&DataKey::Root, &new_root);
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

    /// VULNERABLE: replay protection keys off `sha256(claimant || proof)`
    /// instead of the claimant's address alone.
    ///
    /// # Vulnerability
    /// See module docs. Impact: a claimant added twice to the rolling chain
    /// can claim their allocation once per distinct valid proof.
    pub fn claim(env: Env, claimant: Address, amount: i128, proof: Vec<BytesN<32>>) {
        claimant.require_auth();

        let fingerprint = claim_fingerprint(&env, &claimant, &proof);
        assert!(!is_claimed(&env, &fingerprint), "already claimed");

        let root = get_root(&env).expect("not initialized");
        let mut node = leaf_hash(&env, &claimant, amount);
        for sibling in proof.iter() {
            node = hash_pair(&env, &node, &sibling);
        }
        assert!(node == root, "invalid merkle proof");

        // ✅ (locally) checks-effects-interactions — but keyed on the wrong thing.
        mark_claimed(&env, &fingerprint);

        let token: Address = env.storage().persistent().get(&DataKey::Token).unwrap();
        token::Client::new(&env, &token).transfer(
            &env.current_contract_address(),
            &claimant,
            &amount,
        );

        env.events()
            .publish((symbol_short!("claim"),), (claimant, amount));
    }

    /// View helper exposing whether a given (claimant, proof) fingerprint has
    /// already been used.
    pub fn get_claimed_fingerprint(env: Env, claimant: Address, proof: Vec<BytesN<32>>) -> bool {
        let fingerprint = claim_fingerprint(&env, &claimant, &proof);
        is_claimed(&env, &fingerprint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::Address as _,
        token::{Client as TokenClient, StellarAssetClient},
        Address, BytesN, Env, Vec,
    };

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token_id = env
            .register_stellar_asset_contract_v2(token_admin.clone())
            .address();

        StellarAssetClient::new(&env, &token_id).mint(&admin, &1_000_000);

        (env, token_id, admin)
    }

    /// Baseline: a claimant added exactly once has exactly one valid proof,
    /// and the fingerprint-based replay protection behaves correctly for it.
    #[test]
    fn test_control_single_claim_normal_allocation() {
        let (env, token_id, admin) = setup();

        let contract_id = env.register_contract(None, RollingAirdrop);
        let client = RollingAirdropClient::new(&env, &contract_id);
        client.initialize(&admin, &token_id);

        let c1 = Address::generate(&env);
        let b = Address::generate(&env);

        // Root after adding C1: leaf_hash(C1, 50) (first entry).
        client.add_claimant(&c1, &50i128);
        let leaf_c1 = leaf_hash(&env, &c1, 50i128);

        // Root after adding B once: hash_pair(root_1, leaf(B, 200)).
        client.add_claimant(&b, &200i128);

        client.fund(&400i128);

        let leaf_b = leaf_hash(&env, &b, 200i128);
        let mut proof: Vec<BytesN<32>> = Vec::new(&env);
        proof.push_back(leaf_c1.clone());

        // Sanity check our hand-built proof actually reconstructs the stored root.
        let expected_root = hash_pair(&env, &leaf_c1, &leaf_b);
        assert!(!client.get_claimed_fingerprint(&b, &proof));

        client.claim(&b, &200i128, &proof);

        assert_eq!(TokenClient::new(&env, &token_id).balance(&b), 200i128);
        assert!(client.get_claimed_fingerprint(&b, &proof));

        // Reconstructing the same node from the proof must equal the root that
        // verification checked against.
        let node = hash_pair(&env, &leaf_b, &leaf_c1);
        assert_eq!(node, expected_root);
    }

    /// The same proof cannot be replayed a second time.
    #[test]
    #[should_panic(expected = "already claimed")]
    fn test_control_second_claim_same_proof_panics() {
        let (env, token_id, admin) = setup();

        let contract_id = env.register_contract(None, RollingAirdrop);
        let client = RollingAirdropClient::new(&env, &contract_id);
        client.initialize(&admin, &token_id);

        let c1 = Address::generate(&env);
        let b = Address::generate(&env);

        client.add_claimant(&c1, &50i128);
        let leaf_c1 = leaf_hash(&env, &c1, 50i128);
        client.add_claimant(&b, &200i128);

        client.fund(&400i128);

        let mut proof: Vec<BytesN<32>> = Vec::new(&env);
        proof.push_back(leaf_c1);

        client.claim(&b, &200i128, &proof);
        // Second call with the SAME proof must panic.
        client.claim(&b, &200i128, &proof);
    }

    /// THE EXPLOIT: B is accidentally (or maliciously) appended twice to the
    /// rolling chain with the same allocation. This produces two structurally
    /// different, both cryptographically valid, proofs against the final root:
    ///
    ///   short path: [root_2]                      (through the duplicate append)
    ///   long path:  [leaf(C1,50), leaf(B,200)]     (through the original append)
    ///
    /// Because `claim_fingerprint` hashes the whole proof array, these two
    /// proofs produce two different fingerprints, so B can claim the SAME
    /// 200-token allocation twice — once per proof — draining double what was
    /// ever intended.
    #[test]
    fn test_duplicate_append_enables_double_claim_bug() {
        let (env, token_id, admin) = setup();

        let contract_id = env.register_contract(None, RollingAirdrop);
        let client = RollingAirdropClient::new(&env, &contract_id);
        client.initialize(&admin, &token_id);

        let c1 = Address::generate(&env);
        let b = Address::generate(&env);

        // add C1(50) -> root_1 = leaf(C1,50)
        client.add_claimant(&c1, &50i128);
        let leaf_c1 = leaf_hash(&env, &c1, 50i128);
        let root_1 = leaf_c1.clone();

        // add B(200) -> root_2 = hash_pair(root_1, leaf(B,200))
        client.add_claimant(&b, &200i128);
        let leaf_b = leaf_hash(&env, &b, 200i128);
        let root_2 = hash_pair(&env, &root_1, &leaf_b);

        // add B(200) AGAIN (accidental re-run) -> root_3 = hash_pair(root_2, leaf(B,200))
        client.add_claimant(&b, &200i128);
        let root_3 = hash_pair(&env, &root_2, &leaf_b);

        client.fund(&400i128);

        // Short proof: uses the duplicate insertion's direct top-level link.
        // hash_pair(leaf(B,200), root_2) == root_3
        let mut proof_short: Vec<BytesN<32>> = Vec::new(&env);
        proof_short.push_back(root_2.clone());
        assert_eq!(hash_pair(&env, &leaf_b, &root_2), root_3);

        // Long proof: uses the original insertion's path — reconstruct root_2
        // from (leaf_c1, leaf_b), then combine with B's leaf again for the
        // final link.
        // hash_pair(hash_pair(leaf(B,200), leaf(C1,50)), leaf(B,200)) == root_3
        let mut proof_long: Vec<BytesN<32>> = Vec::new(&env);
        proof_long.push_back(leaf_c1.clone());
        proof_long.push_back(leaf_b.clone());
        let reconstructed_root_2 = hash_pair(&env, &leaf_b, &leaf_c1);
        assert_eq!(reconstructed_root_2, root_2);
        assert_eq!(hash_pair(&env, &reconstructed_root_2, &leaf_b), root_3);

        // Proofs are different arrays -> different fingerprints.
        assert!(!client.get_claimed_fingerprint(&b, &proof_short));
        assert!(!client.get_claimed_fingerprint(&b, &proof_long));

        // First claim, via the short proof, succeeds normally.
        client.claim(&b, &200i128, &proof_short);
        assert_eq!(TokenClient::new(&env, &token_id).balance(&b), 200i128);

        // ❌ Second claim, via the DIFFERENT (long) proof, ALSO succeeds —
        // B ends up with double their intended 200-token allocation.
        client.claim(&b, &200i128, &proof_long);
        assert_eq!(TokenClient::new(&env, &token_id).balance(&b), 400i128);
    }
}
