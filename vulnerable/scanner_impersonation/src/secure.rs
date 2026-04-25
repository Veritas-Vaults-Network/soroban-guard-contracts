//! SECURE mirror: require scanner auth before accepting a scan submission.
//!
//! The only change from the vulnerable version is the addition of
//! `scanner.require_auth()` at the top of `submit_scan`. This ensures the
//! caller must hold the private key of the `scanner` address they claim to be.

use crate::DataKey;
use crate::ScanResult;
use soroban_sdk::{contract, contractimpl, Address, Env, Map, String, Vec};

#[contract]
pub struct SecureRegistry;

#[contractimpl]
impl SecureRegistry {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    pub fn add_scanner(env: Env, scanner: Address) {
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::Scanner(scanner), &true);
    }

    pub fn is_scanner(env: Env, scanner: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Scanner(scanner))
            .unwrap_or(false)
    }

    /// ✅ Fixed: `scanner.require_auth()` ensures only the real scanner can
    /// submit results attributed to its address.
    pub fn submit_scan(
        env: Env,
        scanner: Address,
        contract_address: Address,
        findings_hash: String,
        severity_counts: Map<String, u32>,
    ) {
        // ✅ Caller must prove they control `scanner`.
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

        let history_key = DataKey::ScanHistory(contract_address);
        let mut history: Vec<ScanResult> = env
            .storage()
            .persistent()
            .get(&history_key)
            .unwrap_or(Vec::new(&env));
        history.push_back(result);
        env.storage().persistent().set(&history_key, &history);
    }

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

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
    }
}
