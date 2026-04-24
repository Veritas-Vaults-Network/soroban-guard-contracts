//! On-chain Scan Result Registry
//!
//! Stores scan findings submitted by verified scanners, keyed by the scanned
//! contract address. Supports full history per contract and an enumerable
//! index of all scanned contract addresses.
//!
//! Auth model:
//! - Only the admin can add/remove scanners.
//! - `submit_scan` requires the caller to pass their own `scanner` address and
//!   have signed the transaction (`scanner.require_auth()`). The address is
//!   then checked against the approved-scanner registry.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Map, String, Vec};

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
    /// Ordered list of every contract address that has been scanned at least once
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

        let approved: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Scanner(scanner.clone()))
            .unwrap_or(false);
        if !approved {
            panic!("not a verified scanner");
        }

        let result = ScanResult {
            scanner,
            timestamp: env.ledger().timestamp(),
            findings_hash,
            severity_counts,
        };

        env.storage()
            .persistent()
            .set(&DataKey::LatestScan(contract_address.clone()), &result);

        let history_key = DataKey::ScanHistory(contract_address.clone());
        let mut history: Vec<ScanResult> = env
            .storage()
            .persistent()
            .get(&history_key)
            .unwrap_or(Vec::new(&env));
        history.push_back(result);
        env.storage().persistent().set(&history_key, &history);

        // Append to the scanned-contracts index if not already present.
        let mut index: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::ScannedContracts)
            .unwrap_or(Vec::new(&env));
        if !index.contains(&contract_address) {
            index.push_back(contract_address);
            env.storage()
                .persistent()
                .set(&DataKey::ScannedContracts, &index);
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

    /// Return every contract address that has been scanned at least once.
    pub fn get_all_scanned_contracts(env: Env) -> Vec<Address> {
        env.storage()
            .persistent()
            .get(&DataKey::ScannedContracts)
            .unwrap_or(Vec::new(&env))
    }

    /// Return a page of scanned contract addresses.
    ///
    /// `page` is 0-indexed. Returns an empty vec when `page` is out of range.
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

    #[test]
    fn test_add_scanner_and_submit() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        let hash = String::from_str(&env, "abc123");

        client.add_scanner(&scanner);
        assert!(client.is_scanner(&scanner));

        client.submit_scan(&scanner, &target, &hash, &counts(&env));

        let result = client.get_scan(&target).unwrap();
        assert_eq!(result.scanner, scanner);
        assert_eq!(result.findings_hash, hash);
    }

    #[test]
    fn test_get_history_accumulates() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "hash1"), &counts(&env));
        client.submit_scan(&scanner, &target, &String::from_str(&env, "hash2"), &counts(&env));

        let history = client.get_history(&target);
        assert_eq!(history.len(), 2);
        assert_eq!(history.get(0).unwrap().findings_hash, String::from_str(&env, "hash1"));
        assert_eq!(history.get(1).unwrap().findings_hash, String::from_str(&env, "hash2"));
    }

    #[test]
    #[should_panic]
    fn test_unverified_scanner_cannot_submit() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "badhash"), &counts(&env));
    }

    #[test]
    #[should_panic]
    fn test_remove_scanner_blocks_submission() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        client.remove_scanner(&scanner);
        assert!(!client.is_scanner(&scanner));

        client.submit_scan(&scanner, &target, &String::from_str(&env, "hash"), &counts(&env));
    }

    // ── Scanned-contracts index tests ────────────────────────────────────────

    #[test]
    fn test_get_all_scanned_contracts_returns_all() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let t1 = Address::generate(&env);
        let t2 = Address::generate(&env);
        let t3 = Address::generate(&env);

        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &t1, &String::from_str(&env, "h1"), &counts(&env));
        client.submit_scan(&scanner, &t2, &String::from_str(&env, "h2"), &counts(&env));
        client.submit_scan(&scanner, &t3, &String::from_str(&env, "h3"), &counts(&env));

        let all = client.get_all_scanned_contracts();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_scanning_same_contract_twice_no_duplicate() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "h1"), &counts(&env));
        client.submit_scan(&scanner, &target, &String::from_str(&env, "h2"), &counts(&env));

        let all = client.get_all_scanned_contracts();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn test_paginated_query_returns_correct_slice() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let targets: Vec<Address> = (0..5).map(|_| Address::generate(&env)).collect();

        client.add_scanner(&scanner);
        for t in &targets {
            client.submit_scan(&scanner, t, &String::from_str(&env, "h"), &counts(&env));
        }

        // Page 0, size 2 → first 2
        let page0 = client.get_scanned_contracts_page(&0, &2);
        assert_eq!(page0.len(), 2);

        // Page 1, size 2 → next 2
        let page1 = client.get_scanned_contracts_page(&1, &2);
        assert_eq!(page1.len(), 2);

        // Page 2, size 2 → last 1
        let page2 = client.get_scanned_contracts_page(&2, &2);
        assert_eq!(page2.len(), 1);

        // Pages don't overlap
        assert_ne!(page0.get(0).unwrap(), page1.get(0).unwrap());
    }
}
