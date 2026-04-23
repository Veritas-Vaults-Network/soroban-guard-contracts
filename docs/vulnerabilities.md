# Soroban Vulnerability Reference

Each entry maps to a contract in `vulnerable/` and its secure mirror in `secure/`.

---

## 1. Missing Authorization (`missing_auth`)

**Contract:** `vulnerable/missing_auth` → `secure/secure_vault`

### What it is

Soroban's auth model requires every state-mutating function to call
`address.require_auth()` for the address whose resources are being modified.
Without this call the Soroban host places no restriction on who can invoke the
function — any account can submit a valid transaction.

### Vulnerable code

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    // ❌ No require_auth — anyone can drain `from`
    let from_balance = env.storage().persistent().get(&DataKey::Balance(from.clone())).unwrap_or(0);
    env.storage().persistent().set(&DataKey::Balance(from), &(from_balance - amount));
}
```

### Secure fix

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth(); // ✅ Only `from` can authorise this transfer
    // ...
}
```

### Impact

- Complete fund theft: any attacker can transfer the entire balance of any account.
- Severity: **Critical**

---

## 2. Unchecked Arithmetic (`unchecked_math`)

**Contract:** `vulnerable/unchecked_math` → `secure/secure_vault`

### What it is

Rust's integer types wrap on overflow in `--release` builds unless
`overflow-checks = true` is set in the Cargo profile. Even with that flag,
relying on a panic is not the same as explicitly handling the error. The correct
approach is `checked_mul` / `checked_add` which return `Option` and force the
developer to handle the overflow case.

### Vulnerable code

```rust
// ❌ Raw * — overflows silently without overflow-checks = true
let reward = staked * rate * elapsed;
```

### Secure fix

```rust
let reward = staked
    .checked_mul(rate).expect("reward: overflow")
    .checked_mul(elapsed).expect("reward: overflow");
```

### Impact

- Reward calculation produces wildly incorrect values (wraps to near-zero or
  near-max), enabling either free reward extraction or denial of rewards.
- Severity: **High**

---

## 3. Unprotected Admin Functions (`unprotected_admin`)

**Contract:** `vulnerable/unprotected_admin` → `secure/protected_admin`

### What it is

Admin-only functions (`set_admin`, `upgrade`) that do not verify the caller is
the current admin. Because Soroban does not have implicit access control, any
account can call these functions and take over the contract.

### Vulnerable code

```rust
pub fn set_admin(env: Env, new_admin: Address) {
    // ❌ No require_auth on the current admin
    env.storage().persistent().set(&DataKey::Admin, &new_admin);
}

pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
    // ❌ Anyone can replace the contract WASM
    env.deployer().update_current_contract_wasm(new_wasm_hash);
}
```

### Secure fix

```rust
pub fn set_admin(env: Env, new_admin: Address) {
    let current: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
    current.require_auth(); // ✅ Only the current admin can rotate
    env.storage().persistent().set(&DataKey::Admin, &new_admin);
}
```

### Impact

- Full contract takeover: attacker becomes admin and can drain funds, upgrade
  to malicious WASM, or brick the contract.
- Severity: **Critical**

---

## 4. Unsafe Storage Writes (`unsafe_storage`)

**Contract:** `vulnerable/unsafe_storage` → `secure/protected_admin`

### What it is

A public function that writes to persistent storage keyed by an `Address`
argument without verifying the caller owns that address. Any account can pass
any address and overwrite that account's data.

### Vulnerable code

```rust
pub fn set_profile(env: Env, account: Address, display_name: String, kyc_level: u32) {
    // ❌ No require_auth — anyone can write to any account's slot
    env.storage().persistent().set(&DataKey::Profile(account), &Profile { display_name, kyc_level });
}
```

### Secure fix

```rust
pub fn set_profile(env: Env, account: Address, display_name: String, kyc_level: u32) {
    account.require_auth(); // ✅ Only the account owner can update their profile
    env.storage().persistent().set(&DataKey::Profile(account), &Profile { display_name, kyc_level });
}
```

### Impact

- Data integrity violation: KYC levels, display names, or any stored metadata
  can be forged or wiped by any attacker.
- Severity: **High**

---

## 5. Self-Transfer Balance Inflation (`self_transfer`)

**Contract:** `vulnerable/self_transfer` → `secure/secure_transfer`

### What it is

When `transfer(from, to, amount)` is called with `from == to`, both `get_balance` calls resolve to the same persistent storage slot. The function reads the balance once into two separate variables, subtracts from the first write, then overwrites that slot with the second write — inflating the account balance by `amount` instead of leaving it unchanged.

### Vulnerable code

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth();
    // ❌ No from != to check — self-transfer corrupts balance
    let from_balance = get_balance(&env, &from);
    let to_balance = get_balance(&env, &to); // same slot as from_balance when from == to
    set_balance(&env, &from, from_balance.checked_sub(amount).unwrap());
    set_balance(&env, &to, to_balance.checked_add(amount).unwrap()); // overwrites the subtraction
}
```

### Secure fix

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    assert!(from != to, "self-transfer not allowed"); // ✅ Guard fires before any storage access
    from.require_auth();
    // ...
}
```

### Impact

- Balance inflation: a user can repeatedly self-transfer to inflate their balance without limit.
- Severity: **Medium**

---

## 6. Missing TTL Renewal (`missing_ttl`)

**Contract:** `vulnerable/missing_ttl` → secure mirror in `vulnerable/missing_ttl/src/secure.rs`

### What it is

Soroban persistent storage entries are not permanent by default. Every entry has
a ledger TTL, and once that window passes the entry expires unless the contract
refreshes it with `env.storage().persistent().extend_ttl(...)`.

### Vulnerable code

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth();
    // ❌ No extend_ttl — active balances are never renewed
    env.storage().persistent().set(&from_key, &new_from);
    env.storage().persistent().set(&to_key, &new_to);
}
```

### Secure fix

```rust
let balance: Option<i128> = env.storage().persistent().get(&key);
if balance.is_some() {
    env.storage().persistent().extend_ttl(&key, threshold, extend_to); // ✅ renew on read
}

env.storage().persistent().set(&key, &amount);
env.storage().persistent().extend_ttl(&key, threshold, extend_to); // ✅ renew on write
```

### Impact

- Liveness failure: after roughly the network's max TTL window, balances or
  records disappear and the contract starts reading them as missing.
- Funds are not stolen, but they can become permanently inaccessible.
- Severity: **Low**

---

## General Soroban Security Checklist

| Check                               | Description                                                                                              |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `require_auth` on every mutating fn | Every function that reads or writes resources belonging to an address must call `address.require_auth()` |
| Checked arithmetic                  | Use `checked_add`, `checked_sub`, `checked_mul` for all financial calculations                           |
| Admin gate on privileged fns        | `initialize`, `upgrade`, `set_admin`, `pause` must verify the caller is the stored admin                 |
| Storage key ownership               | Storage keys that include an `Address` must only be written after `address.require_auth()`               |
| No re-initialization                | Guard `initialize` with a check that the contract hasn't already been set up                             |
| TTL renewal for persistent entries  | Long-lived state should call `persistent().extend_ttl(...)` on active reads/writes to avoid expiry      |
