# Contributing to soroban-guard-contracts

Thanks for helping grow the library. This guide covers everything you need to
add a new vulnerable contract example, run the test suite, and get your PR
merged.

---

## Sister repos

| Repo | Purpose |
|---|---|
| [soroban-guard-core](https://github.com/Veritas-Vaults-Network/soroban-guard-core) | CLI scanner that analyses contracts against this library |
| [soroban-guard-web](https://github.com/Veritas-Vaults-Network/soroban-guard-web) | Web dashboard for browsing scan results from the on-chain registry |

---

## 1. Setting up a local Soroban dev environment

### Prerequisites

- Rust toolchain (stable) — install via [rustup](https://rustup.rs)
- `wasm32-unknown-unknown` target
- Stellar CLI (for deploying to testnet, optional for local testing)

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add the WASM target
rustup target add wasm32-unknown-unknown

# Install Stellar CLI (optional — needed for testnet deployment)
cargo install --locked stellar-cli --features opt
```

### Clone and build

```bash
git clone https://github.com/Veritas-Vaults-Network/soroban-guard-contracts
cd soroban-guard-contracts
cargo build
```

---

## 2. Compiling and testing contracts

### Run all tests

```bash
cargo test
```

### Run tests for a single contract

```bash
cargo test -p missing-auth
cargo test -p registry
```

### Build optimised WASM (for deployment)

```bash
cargo build --release --target wasm32-unknown-unknown
# Output: target/wasm32-unknown-unknown/release/<name>.wasm
```

---

## 3. Adding a new vulnerable contract

### Step-by-step

1. **Create the crate**

```bash
mkdir -p vulnerable/<your_name>/src
```

2. **Add `Cargo.toml`**

```toml
[package]
name = "your-name"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
soroban-sdk = { workspace = true }
```

3. **Register it in the workspace** — add `"vulnerable/<your_name>"` to the
   `members` array in the root `Cargo.toml`.

4. **Write the contract** in `src/lib.rs`. See the checklist below.

5. **Add a `#[cfg(test)]` module** with at least 3 tests — one of which must
   demonstrate the vulnerability succeeding (i.e. the bad thing happens without
   a panic).

6. **Document the vulnerability** — add a new section to `docs/vulnerabilities.md`
   following the existing format.

7. **Verify it compiles and tests pass**

```bash
cargo test -p your-name
```

---

## 4. What makes a good vulnerable contract

A good example contract must satisfy all of the following:

### Realistic context
The contract should model something a real developer might write — a token,
vault, staking pool, escrow, DAO, NFT marketplace, etc. Toy contracts with no
business logic are harder to learn from.

### Compilable
The contract must compile against the current workspace `soroban-sdk` version
with zero errors and zero `todo!()` macros. Run `cargo build` before opening
a PR.

### Clearly flawed — not subtly broken
The vulnerability must be obvious enough that a scanner (human or automated)
can identify it from the source. Mark every flaw with a comment:

```rust
// VULNERABILITY: <explain what's wrong and why it matters>
// ❌ Missing: <show what the fix would look like>
```

### One primary vulnerability per contract
Each contract should demonstrate a single class of vulnerability. Combining
multiple issues in one file makes it harder to use as a targeted test case.

### Matching secure mirror
Every vulnerable contract should have a corresponding secure version in
`secure/` with `// ✅ FIX:` comments explaining each change.

### At least 3 tests
- One test that shows normal operation works.
- One test that demonstrates the vulnerability (the bad thing succeeds).
- One test that verifies a boundary condition or edge case.

---

## 5. Code style

- `#![no_std]` on all contracts.
- Use `#[contracttype]` for all storage keys and custom structs.
- No `unwrap()` in production paths — use `.expect("descriptive message")` or
  explicit error handling.
- Keep functions short and single-purpose.
- Run `cargo fmt` before committing.

---

## 6. Commit conventions

This repo targets a minimum of 25 meaningful commits. Each commit should be
scoped to a single logical change:

```
feat(missing_auth): add vulnerable token contract
feat(missing_auth): add test suite demonstrating auth bypass
fix(secure_vault): add balance underflow guard
docs: add missing_auth entry to vulnerabilities.md
```

---

## 7. Opening a PR

1. Fork the repo and create a branch: `feat/vuln-<name>` or `fix/<name>`.
2. Ensure `cargo test` passes with zero failures.
3. Ensure `cargo fmt --check` passes.
4. Fill in the PR template — link to the relevant `docs/vulnerabilities.md`
   section and describe the real-world scenario the contract models.

---

## 8. Adding a new vulnerable/secure pair — full walkthrough

This section walks through every file you need to touch when adding a new
vulnerability class from scratch.

### Naming conventions

| Thing | Convention | Example |
|---|---|---|
| Crate directory | `snake_case` | `vulnerable/missing_auth` |
| Crate name in `Cargo.toml` | `kebab-case` | `missing-auth` |
| Contract struct | `PascalCase` | `MissingAuthToken` |
| Storage key enum | `PascalCase` | `DataKey` |
| Vulnerability comment marker | `// ❌` | `// ❌ Missing: require_auth()` |
| Fix comment marker | `// ✅` | `// ✅ FIX: added require_auth()` |

### Step 1 — Create the vulnerable crate

```
vulnerable/
└── your_vuln_name/
    ├── Cargo.toml
    └── src/
        └── lib.rs
```

`Cargo.toml`:

```toml
[package]
name = "your-vuln-name"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
soroban-sdk = { workspace = true }
```

> If your crate contains more than one `#[contract]` (e.g. a vulnerable + secure
> mirror in the same file), use `crate-type = ["rlib"]` instead — multiple
> contracts in a single `cdylib` produce duplicate exported symbols.

`src/lib.rs` skeleton:

```rust
//! VULNERABLE: <One-line summary>
//!
//! <2-3 sentences describing the contract context and what it does wrong.>
//!
//! VULNERABILITY: <Exact missing guard or wrong pattern>
//! SEVERITY: Critical | High | Medium | Low

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey { /* ... */ }

#[contract]
pub struct YourVulnContract;

#[contractimpl]
impl YourVulnContract {
    /// <What this function does.>
    ///
    /// # Vulnerability
    /// <Why this is dangerous and what an attacker can do.>
    pub fn vulnerable_fn(env: Env, /* args */) {
        // ❌ Missing: <the guard that should be here>
        // ... vulnerable implementation
    }
}
```

### Step 2 — Create the secure mirror

**Option A — separate crate** (preferred when the fix changes the public API):

```
secure/
└── your_secure_name/
    ├── Cargo.toml
    └── src/
        └── lib.rs
```

`Cargo.toml` is identical to the vulnerable one but with `name = "your-secure-name"`.

**Option B — inline `secure.rs`** (preferred when the API is identical):

```
vulnerable/your_vuln_name/src/
├── lib.rs       ← vulnerable contract + pub mod secure;
└── secure.rs    ← SecureYourContract with ✅ fixes
```

In `lib.rs` add `pub mod secure;` and in `secure.rs`:

```rust
use soroban_sdk::{contract, contractimpl, Address, Env};
use super::DataKey; // reuse storage keys from the vulnerable module

#[contract]
pub struct SecureYourContract;

#[contractimpl]
impl SecureYourContract {
    pub fn safe_fn(env: Env, /* args */) {
        // ✅ FIX: <explain the fix>
        // ... secure implementation
    }
}
```

### Step 3 — Register both crates in the workspace

Open the root `Cargo.toml` and add both entries to `members`:

```toml
[workspace]
members = [
    # ... existing members ...
    "vulnerable/your_vuln_name",
    "secure/your_secure_name",   # omit if using inline secure.rs
]
```

### Step 4 — Write the tests

Every contract needs **at least 3 tests**:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    /// 1. Normal operation works as expected.
    #[test]
    fn test_normal_operation() { /* ... */ }

    /// 2. The vulnerability is exploitable (bad thing succeeds without panic).
    #[test]
    fn test_vulnerability_exploitable() { /* ... */ }

    /// 3. The secure version blocks the attack.
    #[test]
    #[should_panic]
    fn test_secure_blocks_attack() { /* ... */ }
}
```

### Step 5 — Add rustdoc to every `pub fn`

Every public function must have a `///` doc comment covering:
- What the function does
- What is missing / why it is dangerous (for vulnerable fns)
- What the fix is (for secure fns)

```rust
/// Transfers `amount` tokens from `from` to `to`.
///
/// # Vulnerability
/// `from.require_auth()` is never called. Any account can drain `from`
/// without holding the corresponding private key.
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
```

### Step 6 — Update `docs/vulnerabilities.md`

Add a new `##` section following the existing format:

```markdown
## N. Your Vulnerability Name (`your_vuln_name`)

**Contract:** `vulnerable/your_vuln_name` → `secure/your_secure_name`

### What it is
...

### Vulnerable code
```rust
// ❌ ...
```

### Secure fix
```rust
// ✅ ...
```

### Impact
- ...
- Severity: **High**
```

### Step 7 — Update the README table

Add a row to the vulnerability table in `README.md`:

```markdown
| `your_vuln_name` | Your class | `secure/your_secure_name` | Fix description |
```

### Step 8 — Verify everything

```bash
cargo build                          # must compile clean
cargo test -p your-vuln-name         # all tests pass
cargo test -p your-secure-name       # all tests pass
cargo doc --workspace --no-deps      # no doc warnings
cargo fmt --check                    # no formatting issues
```

Then open a PR with branch name `feat/vuln-your-vuln-name`, referencing the
issue and linking to the new `docs/vulnerabilities.md` section.

