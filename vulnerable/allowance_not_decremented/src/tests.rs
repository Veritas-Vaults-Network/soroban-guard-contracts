use super::*;
use soroban_sdk::{testutils::Address as _, Address, Env};

#[test]
fn test_transfer_from_vulnerable_first_use_succeeds() {
    let env = Env::default();
    let contract_id = env.register_contract(None, AllowanceNotDecrementedToken);
    let client = AllowanceNotDecrementedTokenClient::new(&env, &contract_id);

    let owner = Address::generate(&env);
    let spender = Address::generate(&env);
    let recipient = Address::generate(&env);

    env.mock_all_auths();
    client.mint(&owner, &1000);
    client.approve(&owner, &spender, &400);

    client.transfer_from(&spender, &owner, &recipient, &400);

    assert_eq!(client.balance(&owner), 600);
    assert_eq!(client.balance(&recipient), 400);
    assert_eq!(client.allowance(&owner, &spender), 400);
}

#[test]
fn test_transfer_from_vulnerable_reuse_succeeds_without_reapproval() {
    let env = Env::default();
    let contract_id = env.register_contract(None, AllowanceNotDecrementedToken);
    let client = AllowanceNotDecrementedTokenClient::new(&env, &contract_id);

    let owner = Address::generate(&env);
    let spender = Address::generate(&env);
    let recipient = Address::generate(&env);

    env.mock_all_auths();
    client.mint(&owner, &1000);
    client.approve(&owner, &spender, &400);

    client.transfer_from(&spender, &owner, &recipient, &400);
    client.transfer_from(&spender, &owner, &recipient, &400);

    assert_eq!(client.balance(&owner), 200);
    assert_eq!(client.balance(&recipient), 800);
    assert_eq!(client.allowance(&owner, &spender), 400);
}

#[test]
fn test_transfer_from_secure_reuse_fails_after_allowance_decrement() {
    let env = Env::default();
    let contract_id = env.register_contract(None, AllowanceNotDecrementedToken);
    let client = AllowanceNotDecrementedTokenClient::new(&env, &contract_id);

    let owner = Address::generate(&env);
    let spender = Address::generate(&env);
    let recipient = Address::generate(&env);

    env.mock_all_auths();
    client.mint(&owner, &1000);
    client.approve(&owner, &spender, &400);

    client.transfer_from_secure(&spender, &owner, &recipient, &400);

    assert_eq!(client.balance(&owner), 600);
    assert_eq!(client.balance(&recipient), 400);
    assert_eq!(client.allowance(&owner, &spender), 0);

    let result = std::panic::catch_unwind(|| {
        client.transfer_from_secure(&spender, &owner, &recipient, &400);
    });

    assert!(result.is_err());
    assert_eq!(client.balance(&owner), 600);
    assert_eq!(client.balance(&recipient), 400);
}
