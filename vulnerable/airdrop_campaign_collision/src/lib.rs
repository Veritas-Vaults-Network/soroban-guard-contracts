//! VULNERABLE: Cross-Campaign Merkle Root Collision
//!
//! This contract implements a multi-campaign airdrop platform: a single
//! deployed contract manages several concurrent/sequential airdrop
//! "campaigns" (e.g. "Season 1", "Season 2"), each identified by a
//! `campaign_id: u32`, each with its own merkle root and reward token. This
//! is a realistic pattern for a platform that wants to run rolling airdrop
//! seasons without redeploying a new contract for every season.
//!
//! VULNERABILITY: `DataKey::MerkleRoot` is **not** namespaced by
//! `campaign_id` — it is a single global storage slot shared by every
//! campaign the contract will ever host. `create_campaign` overwrites this
//! shared slot every time a new campaign is created. The sibling keys right
//! next to it, `DataKey::Token(u32)` and `DataKey::Claimed(u32, Address)`,
//! *are* correctly namespaced by `campaign_id` — which makes the codebase
//! look careful on a quick read and makes the un-namespaced `MerkleRoot` key
//! easy to miss during review. A reviewer scanning for the "usual"
//! cross-campaign double-claim bug will see `Claimed(u32, Address)` looks
//! fine and move on, never noticing that the root itself is shared.
//!
//! Concretely: once campaign 1 is created and funded, any allocation in its
//! merkle tree that has not yet been claimed is valid only as long as
//! `MerkleRoot` still holds campaign 1's root. The moment the admin calls
//! `create_campaign` again to launch campaign 2, `MerkleRoot` is overwritten
//! with campaign 2's root. Every previously-valid proof for campaign 1 now
//! hashes up to the wrong root and fails verification — permanently. There
//! is no recovery function: campaign 1's un-claimed allocations are bricked
//! forever, and the tokens funded for them sit stuck in the contract
//! (`Token(1)` balance), unreachable by their rightful, legitimately
//! eligible claimants.
//!
//! SEVERITY: High
//!
//! FIX: Namespace the root by campaign, i.e. `DataKey::MerkleRoot(u32)`, and
//! read/write it using `campaign_id` exactly like `Token(u32)` and
//! `Claimed(u32, Address)` already are.

#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, xdr::ToXdr, Address, Bytes,
    BytesN, Env, Vec,
};

#[contracttype]
pub enum DataKey {
    Admin,
    // ❌ VULNERABLE: not parameterized by campaign_id — a single global slot
    // shared by every campaign. Should be `MerkleRoot(u32)`.
    MerkleRoot,
    // ✅ correctly namespaced per campaign (deliberate red herring: this
    // sibling key being namespaced correctly makes the un-namespaced
    // `MerkleRoot` above easy to miss on review).
    Token(u32),
    // ✅ correctly namespaced per campaign (also a deliberate red herring:
    // this looks like the "usual" double-claim protection reviewers expect
    // to check, distracting from the shared-root bug).
    Claimed(u32, Address),
}

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

// ❌ VULNERABLE: verification reads the single shared `MerkleRoot` slot
// regardless of which `campaign_id` is being claimed against.
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

fn is_claimed(env: &Env, campaign_id: u32, claimant: &Address) -> bool {
    env.storage()
        .persistent()
        .get(&DataKey::Claimed(campaign_id, claimant.clone()))
        .unwrap_or(false)
}

fn mark_claimed(env: &Env, campaign_id: u32, claimant: &Address) {
    env.storage()
        .persistent()
        .set(&DataKey::Claimed(campaign_id, claimant.clone()), &true);
}

fn get_admin(env: &Env) -> Address {
    env.storage()
        .persistent()
        .get(&DataKey::Admin)
        .expect("not initialized")
}

#[contract]
pub struct CampaignAirdrop;

#[contractimpl]
impl CampaignAirdrop {
    /// Initialize the platform with a single admin who may create campaigns.
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        assert!(
            !env.storage().persistent().has(&DataKey::Admin),
            "already initialized"
        );
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// Admin creates (or, unintentionally, re-creates) an airdrop campaign
    /// with its own merkle root and reward token.
    ///
    /// # Vulnerability
    /// This writes the merkle root to the single shared `DataKey::MerkleRoot`
    /// slot instead of a `campaign_id`-namespaced key. Launching a second
    /// campaign silently overwrites the first campaign's root, permanently
    /// bricking any of its not-yet-claimed allocations.
    pub fn create_campaign(env: Env, campaign_id: u32, merkle_root: BytesN<32>, token: Address) {
        let admin = get_admin(&env);
        admin.require_auth();

        env.storage()
            .persistent()
            .set(&DataKey::Token(campaign_id), &token);

        // ❌ VULNERABLE: overwrites the shared root used by ALL campaigns.
        env.storage()
            .persistent()
            .set(&DataKey::MerkleRoot, &merkle_root);
    }

    /// Admin deposits reward tokens into the pool for a specific campaign.
    pub fn fund(env: Env, campaign_id: u32, amount: i128) {
        let admin = get_admin(&env);
        admin.require_auth();

        let token: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Token(campaign_id))
            .expect("unknown campaign");
        token::Client::new(&env, &token).transfer(&admin, &env.current_contract_address(), &amount);
    }

    /// Claim tokens from `campaign_id` by providing a valid merkle proof.
    /// Marks the address as claimed before transferring
    /// (checks-effects-interactions).
    ///
    /// # Vulnerability
    /// The proof is verified against the single shared `MerkleRoot` slot
    /// (see `verify_merkle_proof`), not a root namespaced by `campaign_id`.
    /// If a later campaign has overwritten that slot, a legitimately
    /// eligible claimant's originally-valid proof will fail verification
    /// forever, even though `campaign_id`, `Token(campaign_id)` and
    /// `Claimed(campaign_id, claimant)` are all otherwise handled correctly.
    pub fn claim(env: Env, campaign_id: u32, claimant: Address, amount: i128, proof: Vec<BytesN<32>>) {
        claimant.require_auth();
        assert!(!is_claimed(&env, campaign_id, &claimant), "already claimed");

        // ❌ VULNERABLE: verifies against the shared, not campaign-scoped, root.
        verify_merkle_proof(&env, &claimant, amount, &proof);

        // ✅ Mark claimed BEFORE transfer (checks-effects-interactions).
        mark_claimed(&env, campaign_id, &claimant);

        let token: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Token(campaign_id))
            .expect("unknown campaign");
        token::Client::new(&env, &token).transfer(
            &env.current_contract_address(),
            &claimant,
            &amount,
        );

        env.events().publish(
            ("claim",),
            (campaign_id, claimant, amount),
        );
    }

    pub fn get_claimed(env: Env, campaign_id: u32, address: Address) -> bool {
        is_claimed(&env, campaign_id, &address)
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

    /// Build a two-leaf merkle tree for `claimant`/`amount` (plus a dummy
    /// sibling leaf for `other`) and return (root, proof-for-claimant).
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

    fn setup() -> (Env, Address) {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);

        let contract_id = env.register_contract(None, CampaignAirdrop);
        let client = CampaignAirdropClient::new(&env, &contract_id);
        client.initialize(&admin);

        (env, contract_id)
    }

    fn new_token(env: &Env, token_admin: &Address, mint_to: &Address, amount: i128) -> Address {
        let token_id = env
            .register_stellar_asset_contract_v2(token_admin.clone())
            .address();
        StellarAssetClient::new(env, &token_id).mint(mint_to, &amount);
        token_id
    }

    /// Control test: with only ONE campaign ever created, the contract
    /// behaves exactly like a normal single-campaign merkle airdrop and a
    /// legitimately eligible claimant can claim successfully. This proves
    /// the bug only manifests once a second campaign is created.
    #[test]
    fn test_control_single_campaign_claim_succeeds() {
        let (env, contract_id) = setup();
        let client = CampaignAirdropClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let claimant_x = Address::generate(&env);
        let other = Address::generate(&env);
        let amount = 100i128;

        let token_a = new_token(&env, &admin, &admin, 1_000);
        let (root_a, proof_a) = build_tree(&env, &claimant_x, amount, &other);

        client.create_campaign(&1u32, &root_a, &token_a);
        client.fund(&1u32, &amount);

        assert!(!client.get_claimed(&1u32, &claimant_x));
        client.claim(&1u32, &claimant_x, &amount, &proof_a);
        assert!(client.get_claimed(&1u32, &claimant_x));

        assert_eq!(
            TokenClient::new(&env, &token_a).balance(&claimant_x),
            amount
        );
    }

    /// Exploit demonstration: campaign 1 is created and funded with a
    /// pending, not-yet-claimed allocation for claimant X. Before X claims,
    /// the admin launches campaign 2 for an unrelated claimant Y, which
    /// overwrites the shared `MerkleRoot` slot. X's originally-valid proof
    /// for campaign 1 now fails to verify — their allocation is permanently
    /// bricked even though `campaign_id` was passed correctly throughout.
    #[test]
    #[should_panic(expected = "invalid merkle proof")]
    fn test_second_campaign_bricks_first_campaigns_pending_claims() {
        let (env, contract_id) = setup();
        let client = CampaignAirdropClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let claimant_x = Address::generate(&env);
        let other_x = Address::generate(&env);
        let amount_x = 100i128;

        let token_a = new_token(&env, &admin, &admin, 1_000);
        let (root_a, proof_a) = build_tree(&env, &claimant_x, amount_x, &other_x);

        client.create_campaign(&1u32, &root_a, &token_a);
        client.fund(&1u32, &amount_x);

        // Admin launches an unrelated second campaign before X claims.
        let claimant_y = Address::generate(&env);
        let other_y = Address::generate(&env);
        let amount_y = 250i128;
        let token_b = new_token(&env, &admin, &admin, 1_000);
        let (root_b, _proof_b) = build_tree(&env, &claimant_y, amount_y, &other_y);
        client.create_campaign(&2u32, &root_b, &token_b);

        // ❌ X's originally-valid proof for campaign 1 no longer verifies:
        // the shared MerkleRoot slot now holds campaign 2's root.
        client.claim(&1u32, &claimant_x, &amount_x, &proof_a);
    }

    /// Companion assertion (split out because the exploit test above uses
    /// `#[should_panic]`): after the shared root has been overwritten by a
    /// second campaign, campaign 1's funded tokens remain stuck in the
    /// contract, un-claimed by their rightful owner — funds are stuck, not
    /// lost to an attacker or transferred anywhere.
    #[test]
    fn test_first_campaigns_funds_remain_stuck_after_collision() {
        let (env, contract_id) = setup();
        let client = CampaignAirdropClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let claimant_x = Address::generate(&env);
        let other_x = Address::generate(&env);
        let amount_x = 100i128;

        let token_a = new_token(&env, &admin, &admin, 1_000);
        let (root_a, _proof_a) = build_tree(&env, &claimant_x, amount_x, &other_x);

        client.create_campaign(&1u32, &root_a, &token_a);
        client.fund(&1u32, &amount_x);

        let claimant_y = Address::generate(&env);
        let other_y = Address::generate(&env);
        let amount_y = 250i128;
        let token_b = new_token(&env, &admin, &admin, 1_000);
        let (root_b, _proof_b) = build_tree(&env, &claimant_y, amount_y, &other_y);
        client.create_campaign(&2u32, &root_b, &token_b);

        // Campaign 1's un-claimed funds are still sitting in the contract.
        assert_eq!(
            TokenClient::new(&env, &token_a).balance(&contract_id),
            amount_x
        );
        assert!(!client.get_claimed(&1u32, &claimant_x));
    }
}
