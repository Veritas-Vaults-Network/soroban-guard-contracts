# `vulnerable/airdrop_campaign_collision`

## Vulnerability: Cross-Campaign Merkle Root Collision

**Severity:** High

## Description

This contract implements a multi-campaign airdrop platform: a single deployed contract hosts several concurrent or sequential airdrop "campaigns" (e.g. "Season 1", "Season 2"), each identified by a `campaign_id`, each with its own merkle root and reward token — a realistic pattern for a platform that wants to run rolling airdrop seasons without redeploying a new contract every time. `DataKey::Token(u32)` and `DataKey::Claimed(u32, Address)` are both correctly namespaced by `campaign_id`, which makes the contract look careful on a quick read. `DataKey::MerkleRoot`, however, is a single global storage slot shared by every campaign the contract will ever host. `create_campaign` overwrites this shared slot every time a new campaign is created, regardless of whether the previous campaign still has un-claimed allocations outstanding. A reviewer scanning for the "usual" cross-campaign double-claim bug sees `Claimed(u32, Address)` looks fine and moves on, never noticing that the root itself is shared.

## Exploit Scenario

1. Admin creates campaign 1 with merkle root `root_a` and funds it. Claimant X is eligible for 100 tokens in campaign 1's tree and has a valid proof against `root_a`.
2. Before X claims, admin launches campaign 2 for an entirely unrelated set of claimants, calling `create_campaign(2, root_b, token_b)`. This overwrites the shared `MerkleRoot` slot with `root_b`.
3. X calls `claim(1, X, 100, proof_a)`. Verification hashes X's leaf up to `root_a` as before, but compares it against the now-stored `root_b` — the proof fails with `"invalid merkle proof"`, even though `campaign_id`, `Token(1)`, and `Claimed(1, X)` were all passed and checked correctly throughout.
4. X's 100 tokens remain funded in the contract (`Token(1)`'s balance) but are permanently unreachable. There is no recovery function — campaign 1's un-claimed allocations are bricked forever the moment a second campaign is created.

## Vulnerable Code

```rust
#[contracttype]
pub enum DataKey {
    Admin,
    // ❌ VULNERABLE: not parameterized by campaign_id — a single global slot
    // shared by every campaign.
    MerkleRoot,
    Token(u32),             // ✅ correctly namespaced
    Claimed(u32, Address),  // ✅ correctly namespaced
}

pub fn create_campaign(env: Env, campaign_id: u32, merkle_root: BytesN<32>, token: Address) {
    let admin = get_admin(&env);
    admin.require_auth();
    env.storage().persistent().set(&DataKey::Token(campaign_id), &token);
    // ❌ VULNERABLE: overwrites the shared root used by ALL campaigns.
    env.storage().persistent().set(&DataKey::MerkleRoot, &merkle_root);
}
```

## Secure Fix

```rust
#[contracttype]
pub enum DataKey {
    Admin,
    // ✅ namespaced exactly like Token(u32) and Claimed(u32, Address).
    MerkleRoot(u32),
    Token(u32),
    Claimed(u32, Address),
}

pub fn create_campaign(env: Env, campaign_id: u32, merkle_root: BytesN<32>, token: Address) {
    let admin = get_admin(&env);
    admin.require_auth();
    env.storage().persistent().set(&DataKey::Token(campaign_id), &token);
    // ✅ each campaign's root lives at its own key and can never collide.
    env.storage()
        .persistent()
        .set(&DataKey::MerkleRoot(campaign_id), &merkle_root);
}
```

`verify_merkle_proof` and `claim` must likewise read `DataKey::MerkleRoot(campaign_id)` instead of the shared `DataKey::MerkleRoot`. With the root namespaced per campaign, launching a new campaign can never affect any other campaign's outstanding, un-claimed allocations.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
