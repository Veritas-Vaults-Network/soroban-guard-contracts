//! On-chain Scan Result Registry
//!
//! Stores scan findings submitted by verified scanners, keyed by the scanned
//! contract address. Supports full history per contract, an enumerable index
//! of all scanned contract addresses, and bulk submission.
//!
//! Auth model:
//! - Only the admin can add/remove scanners.
//! - `submit_scan` / `submit_scans_bulk` require the caller to pass their own
//!   `scanner` address and have signed the transaction. The address is then
//!   checked against the approved-scanner registry.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Map, String, Vec};

/// Maximum number of entries allowed in a single bulk submission.
const MAX_BULK: u32 = 10;

// ── Types ────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub struct ScanResult {
    pub scanner: Address,
    pub timestamp: u64,
    pub findings_hash: String,
    pub severity_counts: Map<String, u32>,
}

#[contracttype]
#[derive(Clone)]
pub struct ScanEntry {
    pub contract_address: Address,
    pub findings_hash: String,
    pub severity_counts: Map<String, u32>,
}

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    Scanner(Address),
    LatestScan(Address),
    ScanHistory(Address),
    ScannedContracts,
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct ScanRegistry;

#[contractimpl]
impl ScanRegistry {
    // ── Initialisation ───────────────────────────────────────────────────────

    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    // ── Scanner management (admin only) ──────────────────────────────────────

    pub fn add_scanner(env: Env, scanner: Address) {
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::Scanner(scanner), &true);
    }

    pub fn remove_scanner(env: Env, scanner: Address) {
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::Scanner(scanner), &false);
    }

    pub fn is_scanner(env: Env, scanner: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Scanner(scanner))
            .unwrap_or(false)
    }

    // ── Scan submission ──────────────────────────────────────────────────────

    pub fn submit_scan(
        env: Env,
        scanner: Address,
        contract_address: Address,
        findings_hash: String,
        severity_counts: Map<String, u32>,
    ) {
        scanner.require_auth();
        Self::assert_approved_scanner(&env, &scanner);

        let result = ScanResult {
            scanner,
            timestamp: env.ledger().timestamp(),
            findings_hash,
            severity_counts,
        };
        Self::store_result(&env, contract_address, result);
    }

    /// Submit multiple scan results in a single call.
    ///
    /// `scanner.require_auth()` is called once. Each entry is processed
    /// individually and emits its own event. Panics if `entries` exceeds
    /// `MAX_BULK` or if the scanner is not approved.
    pub fn submit_scans_bulk(env: Env, scanner: Address, entries: Vec<ScanEntry>) {
        scanner.require_auth();
        Self::assert_approved_scanner(&env, &scanner);

        if entries.len() > MAX_BULK {
            panic!("bulk size exceeds MAX_BULK");
        }

        let ts = env.ledger().timestamp();
        for entry in entries.iter() {
            let result = ScanResult {
                scanner: scanner.clone(),
                timestamp: ts,
                findings_hash: entry.findings_hash.clone(),
                severity_counts: entry.severity_counts.clone(),
            };
            env.events().publish(
                (String::from_str(&env, "scan"), entry.contract_address.clone()),
                entry.findings_hash.clone(),
            );
            Self::store_result(&env, entry.contract_address.clone(), result);
        }
    }

    // ── Queries ──────────────────────────────────────────────────────────────

    pub fn get_scan(env: Env, contract_address: Address) -> Option<ScanResult> {
        env.storage()
            .persistent()
            .get(&DataKey::LatestScan(contract_address))
    }

    pub fn get_history(env: Env, contract_address: Address) -> Vec<ScanResult> {
        env.storage()
            .persistent()
            .get(&DataKey::ScanHistory(contract_address))
            .unwrap_or(Vec::new(&env))
    }

    pub fn get_all_scanned_contracts(env: Env) -> Vec<Address> {
        env.storage()
            .persistent()
            .get(&DataKey::ScannedContracts)
            .unwrap_or(Vec::new(&env))
    }

    pub fn get_scanned_contracts_page(env: Env, page: u32, page_size: u32) -> Vec<Address> {
        let all: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::ScannedContracts)
            .unwrap_or(Vec::new(&env));

        let start = (page * page_size) as usize;
        let mut result = Vec::new(&env);
        for i in start..(start + page_size as usize) {
            match all.get(i as u32) {
                Some(addr) => result.push_back(addr),
                None => break,
            }
        }
        result
    }

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

    fn assert_approved_scanner(env: &Env, scanner: &Address) {
        let approved: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Scanner(scanner.clone()))
            .unwrap_or(false);
        if !approved {
            panic!("not a verified scanner");
        }
    }

    fn store_result(env: &Env, contract_address: Address, result: ScanResult) {
        env.storage()
            .persistent()
            .set(&DataKey::LatestScan(contract_address.clone()), &result);

        let history_key = DataKey::ScanHistory(contract_address.clone());
        let mut history: Vec<ScanResult> = env
            .storage()
            .persistent()
            .get(&history_key)
            .unwrap_or(Vec::new(env));
        history.push_back(result);
        env.storage().persistent().set(&history_key, &history);

        let mut index: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::ScannedContracts)
            .unwrap_or(Vec::new(env));
        if !index.contains(&contract_address) {
            index.push_back(contract_address);
            env.storage()
                .persistent()
                .set(&DataKey::ScannedContracts, &index);
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{map, testutils::Address as _, Address, Env, String};

    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        let contract_id = env.register_contract(None, ScanRegistry);
        let admin = Address::generate(&env);
        let scanner = Address::generate(&env);
        env.mock_all_auths();
        ScanRegistryClient::new(&env, &contract_id).initialize(&admin);
        (env, contract_id, admin, scanner)
    }

    fn counts(env: &Env) -> Map<String, u32> {
        map![env, (String::from_str(env, "low"), 1u32)]
    }

    fn entry(env: &Env, addr: &Address, hash: &str) -> ScanEntry {
        ScanEntry {
            contract_address: addr.clone(),
            findings_hash: String::from_str(env, hash),
            severity_counts: counts(env),
        }
    }

    // ── Existing tests ───────────────────────────────────────────────────────

    #[test]
    fn test_add_scanner_and_submit() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);
        let hash = String::from_str(&env, "abc123");

        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &target, &hash, &counts(&env));

        let result = client.get_scan(&target).unwrap();
        assert_eq!(result.findings_hash, hash);
    }

    #[test]
    fn test_get_history_accumulates() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "h1"), &counts(&env));
        client.submit_scan(&scanner, &target, &String::from_str(&env, "h2"), &counts(&env));

        assert_eq!(client.get_history(&target).len(), 2);
    }

    #[test]
    #[should_panic]
    fn test_unverified_scanner_cannot_submit() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "h"), &counts(&env));
    }

    #[test]
    #[should_panic]
    fn test_remove_scanner_blocks_submission() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        client.remove_scanner(&scanner);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "h"), &counts(&env));
    }

    // ── Bulk submission tests ────────────────────────────────────────────────

    #[test]
    fn test_bulk_submit_three_scans() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let t1 = Address::generate(&env);
        let t2 = Address::generate(&env);
        let t3 = Address::generate(&env);

        client.add_scanner(&scanner);

        let mut entries = Vec::new(&env);
        entries.push_back(entry(&env, &t1, "h1"));
        entries.push_back(entry(&env, &t2, "h2"));
        entries.push_back(entry(&env, &t3, "h3"));

        client.submit_scans_bulk(&scanner, &entries);

        assert_eq!(client.get_scan(&t1).unwrap().findings_hash, String::from_str(&env, "h1"));
        assert_eq!(client.get_scan(&t2).unwrap().findings_hash, String::from_str(&env, "h2"));
        assert_eq!(client.get_scan(&t3).unwrap().findings_hash, String::from_str(&env, "h3"));
    }

    #[test]
    fn test_bulk_results_appear_in_get_scan() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);

        let mut entries = Vec::new(&env);
        entries.push_back(entry(&env, &target, "bulk_hash"));
        client.submit_scans_bulk(&scanner, &entries);

        assert!(client.get_scan(&target).is_some());
    }

    #[test]
    #[should_panic(expected = "bulk size exceeds MAX_BULK")]
    fn test_bulk_above_max_panics() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        client.add_scanner(&scanner);

        let mut entries = Vec::new(&env);
        for _ in 0..(MAX_BULK + 1) {
            let t = Address::generate(&env);
            entries.push_back(entry(&env, &t, "h"));
        }
        client.submit_scans_bulk(&scanner, &entries);
    }

    #[test]
    #[should_panic(expected = "not a verified scanner")]
    fn test_unverified_scanner_cannot_bulk_submit() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        let mut entries = Vec::new(&env);
        entries.push_back(entry(&env, &target, "h"));
        client.submit_scans_bulk(&scanner, &entries);
    }

    // ── Scanned-contracts index tests ────────────────────────────────────────

    #[test]
    fn test_get_all_scanned_contracts_returns_all() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        client.add_scanner(&scanner);
        for _ in 0..3 {
            let t = Address::generate(&env);
            client.submit_scan(&scanner, &t, &String::from_str(&env, "h"), &counts(&env));
        }

        assert_eq!(client.get_all_scanned_contracts().len(), 3);
    }

    #[test]
    fn test_scanning_same_contract_twice_no_duplicate() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "h1"), &counts(&env));
        client.submit_scan(&scanner, &target, &String::from_str(&env, "h2"), &counts(&env));

        assert_eq!(client.get_all_scanned_contracts().len(), 1);
    }

    #[test]
    fn test_paginated_query_returns_correct_slice() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        client.add_scanner(&scanner);
        for _ in 0..5 {
            let t = Address::generate(&env);
            client.submit_scan(&scanner, &t, &String::from_str(&env, "h"), &counts(&env));
        }

        assert_eq!(client.get_scanned_contracts_page(&0, &2).len(), 2);
        assert_eq!(client.get_scanned_contracts_page(&1, &2).len(), 2);
        assert_eq!(client.get_scanned_contracts_page(&2, &2).len(), 1);
    }
}
