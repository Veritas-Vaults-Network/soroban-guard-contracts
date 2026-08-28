# `vulnerable/merkle_duplicate_siblings`

## Vulnerability: Merkle Duplicate Siblings (Proof-Content-Based Replay Protection)

**Severity:** Critical

## Description

`RollingAirdrop` implements an incrementally-growing ("rolling") merkle airdrop: instead of publishing one fixed tree up front, the admin appends one claimant at a time as they become eligible, chaining the root with `new_root = hash_pair(old_root, leaf_hash(claimant, amount))`. This is a legitimate pattern for referral- or KYC-gated airdrops approved on a rolling basis.

The bug is in how replay protection is keyed. `claim_fingerprint()` hashes the claimant **together with the entire proof array** (`sha256(claimant || proof[0] || proof[1] || ...)`) and marks that fingerprint claimed, instead of marking the claimant's address claimed. Separately, `add_claimant()` never checks whether a claimant has already been added — it's a pure append. Put together: if the admin appends the same claimant twice (an easy operational slip, e.g. re-running a batch-approval script), that claimant now has **two different arrays of sibling hashes** that both verify against the current root. Each proof array hashes to a different fingerprint, so each one is independently, and fully, claimable.

## The two paths, in prose

Say the chain is built as: add `C1` (amount 50) first, giving `root_1 = leaf(C1)`. Then add `B` (amount 200) once, giving `root_2 = hash_pair(root_1, leaf(B))`. Then — by mistake — add `B` (amount 200) *again*, giving the final stored root `root_3 = hash_pair(root_2, leaf(B))`.

`B` now holds two valid proofs against `root_3`:

- **Short path** — walk up through the duplicate append's own top-level link: `proof_short = [root_2]`. Verification does `hash_pair(leaf(B), root_2) == root_3`. ✔
- **Long path** — walk up through the *original* insertion point, reconstructing `root_2` from scratch and then re-combining with `B`'s own leaf for the final link: `proof_long = [leaf(C1), leaf(B)]`. Verification does `hash_pair(hash_pair(leaf(B), leaf(C1)), leaf(B)) == root_3`. ✔

Both are legitimate merkle proofs for `(B, 200)` against the one root actually stored on-chain. Because `proof_short != proof_long`, `claim_fingerprint(B, proof_short) != claim_fingerprint(B, proof_long)`, so submitting first one and then the other both succeed — `B` collects 200 tokens twice for a single 200-token allocation.

## Exploit Scenario

1. Admin adds `C1` with amount 50 (first entry: `Root = leaf(C1, 50)`).
2. Admin adds `B` with amount 200 (`Root = hash_pair(old_root, leaf(B, 200))`), call this `root_2`.
3. Admin accidentally re-runs the approval step and adds `B` with amount 200 again (`Root = hash_pair(root_2, leaf(B, 200))`), call this `root_3` — the final stored root. `add_claimant` never checked B wasn't already present.
4. `B` computes `proof_short = [root_2]` and calls `claim(B, 200, proof_short)` — succeeds, `B` receives 200 tokens.
5. `B` computes the *different* `proof_long = [leaf(C1, 50), leaf(B, 200)]`, which also verifies against `root_3`, and calls `claim(B, 200, proof_long)` — this ALSO succeeds, because its fingerprint is different from step 4's. `B` receives another 200 tokens, doubling their intended allocation.

## Vulnerable Code

```rust
// ❌ VULNERABLE: fingerprint binds replay-protection to the entire proof
// array rather than to the claimant alone.
fn claim_fingerprint(env: &Env, claimant: &Address, proof: &Vec<BytesN<32>>) -> BytesN<32> {
    let mut buf = Bytes::new(env);
    buf.append(&claimant.to_xdr(env));
    for sibling in proof.iter() {
        buf.append(&Bytes::from(sibling.clone()));
    }
    env.crypto().sha256(&buf).into()
}

// ❌ VULNERABLE: no dedup check — the same claimant can be appended more than once.
pub fn add_claimant(env: Env, claimant: Address, amount: i128) {
    let admin: Address = env.storage().persistent().get(&DataKey::Admin).expect("not initialized");
    admin.require_auth();
    let new_leaf = leaf_hash(&env, &claimant, amount);
    let new_root = match get_root(&env) {
        Some(old_root) => hash_pair(&env, &old_root, &new_leaf),
        None => new_leaf,
    };
    env.storage().persistent().set(&DataKey::Root, &new_root);
}
```

## Secure Fix

```rust
// ✅ SECURE: key replay protection by claimant address alone, independent of
// which valid proof was used to reach the root.
fn is_claimed(env: &Env, claimant: &Address) -> bool {
    env.storage().persistent().get(&DataKey::Claimed(claimant.clone())).unwrap_or(false)
}

fn mark_claimed(env: &Env, claimant: &Address) {
    env.storage().persistent().set(&DataKey::Claimed(claimant.clone()), &true);
}

pub fn claim(env: Env, claimant: Address, amount: i128, proof: Vec<BytesN<32>>) {
    claimant.require_auth();
    assert!(!is_claimed(&env, &claimant), "already claimed");
    // ... verify proof against Root ...
    mark_claimed(&env, &claimant); // ✅ keyed by claimant, not by proof content
    // ... transfer ...
}
```

See [`secure/secure_airdrop`](../../secure/secure_airdrop) for the general pattern of keying `Claimed` by `Address`. A fully correct rolling-chain implementation would additionally have `add_claimant` reject (or explicitly special-case) re-adding an already-present claimant, since duplicate structural paths to the root are the root cause enabling this bug regardless of how replay protection is keyed.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
