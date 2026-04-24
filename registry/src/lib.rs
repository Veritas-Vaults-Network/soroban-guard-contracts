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

        // Emit structured event for off-chain indexers.
        env.events().publish(
            (symbol_short!("scan"), symbol_short!("submitted")),
            (scanner, contract_address, findings_hash),
        );
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

    /// Retrieve the full scan history for a contract address.
    ///
    /// # Arguments
    /// * `contract_address` - The contract address to look up.
    ///
    /// # Returns
    /// A vector of all `ScanResult`s submitted for this contract, ordered oldest
    /// to newest.
    pub fn get_history(env: Env, contract_address: Address) -> Vec<ScanResult> {
        env.storage()
            .persistent()
            .get(&DataKey::ScanHistory(contract_address))
            .unwrap_or(Vec::new(&env))
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

        let history = client.get_history(&target);
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

    #[test]
    fn test_submit_scan_emits_event() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        let hash = String::from_str(&env, "deadbeef");
        let counts: Map<String, u32> = map![&env, (String::from_str(&env, "high"), 1u32)];

        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &target, &hash, &counts);

        let events = env.events().all();
        // Last event should be the scan submitted event.
        let last = events.last().unwrap();
        assert_eq!(
            last.1,
            soroban_sdk::vec![
                &env,
                soroban_sdk::Val::from(symbol_short!("scan")),
                soroban_sdk::Val::from(symbol_short!("submitted")),
            ]
        );
    }

    #[test]
    fn test_add_scanner_emits_event() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        client.add_scanner(&scanner);

        let events = env.events().all();
        let last = events.last().unwrap();
        assert_eq!(
            last.1,
            soroban_sdk::vec![
                &env,
                soroban_sdk::Val::from(symbol_short!("scanner")),
                soroban_sdk::Val::from(symbol_short!("added")),
            ]
        );
    }

    #[test]
    fn test_remove_scanner_emits_event() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        client.add_scanner(&scanner);
        client.remove_scanner(&scanner);

        let events = env.events().all();
        let last = events.last().unwrap();
        assert_eq!(
            last.1,
            soroban_sdk::vec![
                &env,
                soroban_sdk::Val::from(symbol_short!("scanner")),
                soroban_sdk::Val::from(symbol_short!("removed")),
            ]
        );
    }
}
