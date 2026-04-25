//! On-chain Scan Result Registry
//!
//! Stores scan findings submitted by verified scanners, keyed by the scanned
//! contract address. Supports full history per contract.
//!
//! Auth model:
//! - Only the admin can add/remove scanners.
//! - `submit_scan` requires the caller to pass their own `scanner` address and
//!   have signed the transaction (`scanner.require_auth()`). The address is
//!   then checked against the approved-scanner registry.

#![no_std]
extern crate alloc;
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, Map, String, Vec};

// ── Types ────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub struct ScanResult {
    pub scanner: Address,
    pub timestamp: u64,
    pub findings_hash: String,
    /// e.g. {"critical": 1, "high": 2, "medium": 0, "low": 3}
    pub severity_counts: Map<String, u32>,
}

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    /// true = approved, false / absent = not approved
    Scanner(Address),
    /// Most recent scan result for a contract address
    LatestScan(Address),
    /// Full ordered history of scan results for a contract address
    ScanHistory(Address),
    /// Reputation score for a scanner address (i32, default 0)
    ScannerScore(Address),
    /// Dedup guard: (scanner, contract, ledger_sequence, findings_hash) — stored in temporary storage
    DedupKey(Address, Address, u32, String),
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct ScanRegistry;

#[contractimpl]
impl ScanRegistry {
    // ── Initialisation ───────────────────────────────────────────────────────

    /// Initialize the registry with an admin address.
    ///
    /// # Panics
    /// Panics if the registry has already been initialized.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    // ── Scanner management (admin only) ──────────────────────────────────────

    /// Add a scanner to the approved list.
    ///
    /// # Arguments
    /// * `scanner` - The address to approve for submitting scans.
    ///
    /// # Panics
    /// Panics if the caller is not the admin.
    ///
    /// # Events
    /// Emits `("scanner", "added", scanner)`.
    pub fn add_scanner(env: Env, scanner: Address) {
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::Scanner(scanner.clone()), &true);
        env.events()
            .publish((symbol_short!("scanner"), symbol_short!("added")), scanner);
    }

    /// Remove a scanner from the approved list.
    ///
    /// # Arguments
    /// * `scanner` - The address to remove from the approved list.
    ///
    /// # Panics
    /// Panics if the caller is not the admin.
    ///
    /// # Events
    /// Emits `("scanner", "removed", scanner)`.
    pub fn remove_scanner(env: Env, scanner: Address) {
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::Scanner(scanner.clone()), &false);
        env.events()
            .publish((symbol_short!("scanner"), symbol_short!("removed")), scanner);
    }

    /// Check whether an address is an approved scanner.
    ///
    /// # Arguments
    /// * `scanner` - The address to check.
    ///
    /// # Returns
    /// `true` if the scanner is approved, `false` otherwise.
    pub fn is_scanner(env: Env, scanner: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Scanner(scanner))
            .unwrap_or(false)
    }

    // ── Scan submission ──────────────────────────────────────────────────────

    /// Submit a scan result for `contract_address`.
    ///
    /// `scanner` must be a verified scanner address and must have signed this
    /// transaction. `findings_hash` is a hex-encoded SHA-256 of the full
    /// findings JSON. `severity_counts` maps severity labels to counts.
    ///
    /// # Events
    /// Emits `("scan", "submitted", (scanner, contract_address, findings_hash))`.
    pub fn submit_scan(
        env: Env,
        scanner: Address,
        contract_address: Address,
        findings_hash: String,
        severity_counts: Map<String, u32>,
    ) {
        // 1. The scanner must have signed this transaction.
        scanner.require_auth();

        // 2. The scanner must be in the approved list.
        let approved: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Scanner(scanner.clone()))
            .unwrap_or(false);
        if !approved {
            panic!("not a verified scanner");
        }

        // 3. Reject duplicate (scanner, contract, ledger, hash) submissions within the same ledger.
        let dedup_key = DataKey::DedupKey(scanner.clone(), contract_address.clone(), env.ledger().sequence(), findings_hash.clone());
        if env.storage().temporary().has(&dedup_key) {
            panic!("duplicate submission");
        }
        env.storage().temporary().set(&dedup_key, &true);

        // Keep a copy for the score key before scanner is moved into ScanResult.
        let score_key = DataKey::ScannerScore(scanner.clone());

        let result = ScanResult {
            scanner: scanner.clone(),
            timestamp: env.ledger().timestamp(),
            findings_hash: findings_hash.clone(),
            severity_counts,
        };

        // Overwrite latest result.
        env.storage()
            .persistent()
            .set(&DataKey::LatestScan(contract_address.clone()), &result);

        // Append to history.
        let history_key = DataKey::ScanHistory(contract_address.clone());
        let mut history: Vec<ScanResult> = env
            .storage()
            .persistent()
            .get(&history_key)
            .unwrap_or(Vec::new(&env));
        history.push_back(result);
        env.storage().persistent().set(&history_key, &history);

        // Increment scanner reputation score.
        let score: i32 = env
            .storage()
            .persistent()
            .get(&score_key)
            .unwrap_or(0i32);
        env.storage()
            .persistent()
            .set(&score_key, &score.saturating_add(1));
    }

    // ── Reputation ───────────────────────────────────────────────────────────

    /// Dispute a scanner's submission (admin only), decrementing their score by 1.
    ///
    /// # Arguments
    /// * `scanner` - The scanner whose score should be decremented.
    ///
    /// # Panics
    /// Panics if the caller is not the admin.
    pub fn dispute_scan(env: Env, scanner: Address) {
        Self::require_admin(&env);
        let score_key = DataKey::ScannerScore(scanner);
        let score: i32 = env
            .storage()
            .persistent()
            .get(&score_key)
            .unwrap_or(0i32);
        env.storage()
            .persistent()
            .set(&score_key, &score.saturating_sub(1));
    }

    /// Return the reputation score for a scanner (defaults to 0).
    ///
    /// # Arguments
    /// * `scanner` - The scanner address to query.
    pub fn get_scanner_score(env: Env, scanner: Address) -> i32 {
        env.storage()
            .persistent()
            .get(&DataKey::ScannerScore(scanner))
            .unwrap_or(0i32)
    }

    // ── Queries ──────────────────────────────────────────────────────────────

    /// Retrieve the latest scan result for a contract address.
    ///
    /// # Arguments
    /// * `contract_address` - The contract address to look up.
    ///
    /// # Returns
    /// The most recent `ScanResult`, or `None` if no scan exists.
    pub fn get_scan(env: Env, contract_address: Address) -> Option<ScanResult> {
        env.storage()
            .persistent()
            .get(&DataKey::LatestScan(contract_address))
    }

    /// Return the total number of scan results stored for a contract address.
    ///
    /// # Arguments
    /// * `contract_address` - The contract address to look up.
    ///
    /// # Returns
    /// The number of `ScanResult`s in the history (0 if none).
    pub fn get_history_len(env: Env, contract_address: Address) -> u32 {
        let history: Vec<ScanResult> = env
            .storage()
            .persistent()
            .get(&DataKey::ScanHistory(contract_address))
            .unwrap_or(Vec::new(&env));
        history.len()
    }

    /// Retrieve a bounded page of scan history for a contract address.
    ///
    /// Results are ordered oldest to newest. `limit` is capped at 50.
    /// If `offset` is beyond the end of the history, an empty vector is returned.
    ///
    /// # Arguments
    /// * `contract_address` - The contract address to look up.
    /// * `offset`           - Zero-based index of the first record to return.
    /// * `limit`            - Maximum number of records to return (capped at 50).
    pub fn get_history_page(
        env: Env,
        contract_address: Address,
        offset: u32,
        limit: u32,
    ) -> Vec<ScanResult> {
        const MAX_LIMIT: u32 = 50;
        let effective_limit = limit.min(MAX_LIMIT);

        let history: Vec<ScanResult> = env
            .storage()
            .persistent()
            .get(&DataKey::ScanHistory(contract_address))
            .unwrap_or(Vec::new(&env));

        let total = history.len();
        if offset >= total {
            return Vec::new(&env);
        }

        let end = (offset + effective_limit).min(total);
        let mut result: Vec<ScanResult> = Vec::new(&env);
        for i in offset..end {
            result.push_back(history.get(i).unwrap());
        }
        result
    }

    /// Return the admin address of the registry.
    ///
    /// # Returns
    /// The admin `Address`.
    ///
    /// # Panics
    /// Panics if the registry has not been initialized.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{map, testutils::Address as _, testutils::Events, Address, Env, String};

    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        let contract_id = env.register_contract(None, ScanRegistry);
        let admin = Address::generate(&env);
        let scanner = Address::generate(&env);
        env.mock_all_auths();
        ScanRegistryClient::new(&env, &contract_id).initialize(&admin);
        (env, contract_id, admin, scanner)
    }

    #[test]
    fn test_add_scanner_and_submit() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        let hash = String::from_str(&env, "abc123");
        let counts: Map<String, u32> = map![
            &env,
            (String::from_str(&env, "critical"), 1u32),
            (String::from_str(&env, "high"), 2u32)
        ];

        client.add_scanner(&scanner);
        assert!(client.is_scanner(&scanner));

        client.submit_scan(&scanner, &target, &hash, &counts);

        let result = client.get_scan(&target).unwrap();
        assert_eq!(result.scanner, scanner);
        assert_eq!(result.findings_hash, hash);
    }

    #[test]
    fn test_get_history_accumulates() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        let counts: Map<String, u32> = map![&env, (String::from_str(&env, "low"), 1u32)];

        client.add_scanner(&scanner);

        client.submit_scan(&scanner, &target, &String::from_str(&env, "hash1"), &counts);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "hash2"), &counts);

        // Use get_history_page to read both records (offset=0, limit=50).
        let history = client.get_history_page(&target, &0, &50);
        assert_eq!(history.len(), 2);
        assert_eq!(
            history.get(0).unwrap().findings_hash,
            String::from_str(&env, "hash1")
        );
        assert_eq!(
            history.get(1).unwrap().findings_hash,
            String::from_str(&env, "hash2")
        );
    }

    /// Unregistered address cannot submit scans.
    #[test]
    #[should_panic]
    fn test_unverified_scanner_cannot_submit() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        let counts: Map<String, u32> = map![&env, (String::from_str(&env, "low"), 0u32)];

        // scanner was never added — should panic.
        client.submit_scan(
            &scanner,
            &target,
            &String::from_str(&env, "badhash"),
            &counts,
        );
    }

    #[test]
    #[should_panic]
    fn test_remove_scanner_blocks_submission() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        let counts: Map<String, u32> = map![&env, (String::from_str(&env, "low"), 0u32)];

        client.add_scanner(&scanner);
        client.remove_scanner(&scanner);

        assert!(!client.is_scanner(&scanner));

        // Attempting to submit after removal should panic.
        client.submit_scan(&scanner, &target, &String::from_str(&env, "hash"), &counts);
    }

    // ── Reputation tests ─────────────────────────────────────────────────────

    #[test]
    fn test_score_starts_at_zero() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        assert_eq!(client.get_scanner_score(&scanner), 0);
    }

    #[test]
    fn test_score_increments_on_submit() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        let counts: Map<String, u32> = map![&env, (String::from_str(&env, "low"), 0u32)];

        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "h1"), &counts);
        assert_eq!(client.get_scanner_score(&scanner), 1);

        client.submit_scan(&scanner, &target, &String::from_str(&env, "h2"), &counts);
        assert_eq!(client.get_scanner_score(&scanner), 2);
    }

    #[test]
    fn test_score_decrements_on_admin_dispute() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        let counts: Map<String, u32> = map![&env, (String::from_str(&env, "low"), 0u32)];

        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "h1"), &counts);
        assert_eq!(client.get_scanner_score(&scanner), 1);

        client.dispute_scan(&scanner);
        assert_eq!(client.get_scanner_score(&scanner), 0);
    }

    // ── Pagination tests ──────────────────────────────────────────────────────

    fn submit_n_scans(client: &ScanRegistryClient, scanner: &Address, target: &Address, n: u32, env: &Env) {
        let counts: Map<String, u32> = map![env, (String::from_str(env, "low"), 0u32)];
        for i in 0..n {
            // Use unique hashes by encoding the index into the string.
            let hash = String::from_str(env, &alloc::format!("hash{i}"));
            client.submit_scan(scanner, target, &hash, &counts);
        }
    }

    /// Demonstrates the unbounded-read vulnerability: inserting 200 records and
    /// reading them all back via get_history_page with a large limit returns all 200.
    /// (This is the pattern that would brick the node if get_history were unbounded.)
    #[test]
    fn test_200_records_unbounded_demo() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        submit_n_scans(&client, &scanner, &target, 200, &env);

        assert_eq!(client.get_history_len(&target), 200);
    }

    /// After the fix, get_history_page with limit=50 returns exactly 50 records
    /// even when more are stored.
    #[test]
    fn test_limit_50_returns_exactly_50() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        submit_n_scans(&client, &scanner, &target, 200, &env);

        let page = client.get_history_page(&target, &0, &50);
        assert_eq!(page.len(), 50);
    }

    /// Requesting limit=100 (above the cap) is silently capped to 50.
    #[test]
    fn test_limit_above_cap_is_capped_to_50() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        submit_n_scans(&client, &scanner, &target, 200, &env);

        let page = client.get_history_page(&target, &0, &100);
        assert_eq!(page.len(), 50);
    }

    /// offset + limit beyond the Vec length returns only the remaining records
    /// without panicking.
    #[test]
    fn test_offset_plus_limit_beyond_end_returns_remainder() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        submit_n_scans(&client, &scanner, &target, 10, &env);

        // offset=8, limit=50 → only 2 records remain (indices 8 and 9).
        let page = client.get_history_page(&target, &8, &50);
        assert_eq!(page.len(), 2);
        assert_eq!(page.get(0).unwrap().findings_hash, String::from_str(&env, "hash8"));
        assert_eq!(page.get(1).unwrap().findings_hash, String::from_str(&env, "hash9"));
    }

    #[test]
    fn test_offset_beyond_end_returns_empty() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        submit_n_scans(&client, &scanner, &target, 3, &env);

        let page = client.get_history_page(&target, &10, &50);
        assert_eq!(page.len(), 0);
    }

    #[test]
    fn test_get_history_len() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        assert_eq!(client.get_history_len(&target), 0);

        submit_n_scans(&client, &scanner, &target, 4, &env);
        assert_eq!(client.get_history_len(&target), 4);
    }

    #[test]
    #[should_panic]
    fn test_non_admin_cannot_dispute() {
        // Use a fresh env with no mocked auths so require_auth panics.
        let env = Env::default();
        let contract_id = env.register_contract(None, ScanRegistry);
        let admin = Address::generate(&env);
        let scanner = Address::generate(&env);

        env.mock_all_auths();
        ScanRegistryClient::new(&env, &contract_id).initialize(&admin);

        // Clear all mocks — no auth is satisfied from here on.
        env.mock_auths(&[]);

        // admin.require_auth() inside dispute_scan is not satisfied → panic.
        ScanRegistryClient::new(&env, &contract_id).dispute_scan(&scanner);
    }

    // ── Deduplication tests ───────────────────────────────────────────────────

    /// Demonstrates the bug: without the fix, the same scanner could submit the
    /// same hash twice in the same ledger and both records would appear.
    /// With the fix applied, the second call panics with "duplicate submission".
    #[test]
    #[should_panic(expected = "duplicate submission")]
    fn test_duplicate_same_hash_same_ledger_panics() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        let hash = String::from_str(&env, "abc123");
        let counts: Map<String, u32> = map![&env, (String::from_str(&env, "low"), 0u32)];

        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &target, &hash, &counts);
        // Second call with the same (scanner, contract, ledger) → must panic.
        client.submit_scan(&scanner, &target, &hash, &counts);
    }

    /// After the fix, a duplicate submission in the same ledger panics.
    #[test]
    #[should_panic(expected = "duplicate submission")]
    fn test_duplicate_submission_rejected() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        let hash = String::from_str(&env, "deadbeef");
        let counts: Map<String, u32> = map![&env, (String::from_str(&env, "critical"), 1u32)];

        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &target, &hash, &counts);
        client.submit_scan(&scanner, &target, &hash, &counts);
    }

    /// A different findings_hash in the same ledger is a distinct submission and must succeed.
    #[test]
    fn test_different_hash_same_ledger_allowed() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        let counts: Map<String, u32> = map![&env, (String::from_str(&env, "low"), 0u32)];

        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "hash_a"), &counts);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "hash_b"), &counts);

        assert_eq!(client.get_history_len(&target), 2);
    }
}
