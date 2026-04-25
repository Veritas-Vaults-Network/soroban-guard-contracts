use super::*;
use soroban_sdk::{testutils::Address as _, Address, Env};

fn setup(env: &Env) -> (FlashLoanNoCheckClient, BorrowerClient, Address, Address) {
    let lender_id = env.register_contract(None, FlashLoanNoCheck);
    let borrower_id = env.register_contract(None, Borrower);
    let lender_client = FlashLoanNoCheckClient::new(&env, &lender_id);
    let borrower_client = BorrowerClient::new(&env, &borrower_id);
    lender_client.initialize(&lender_id);
    let borrower_address = borrower_id.clone();
    (lender_client, borrower_client, borrower_address, lender_id)
}

#[test]
fn test_honest_borrower_repay_succeeds() {
    let env = Env::default();
    let (lender, borrower, borrower_address, lender_id) = setup(&env);

    lender.mint(&lender_id, &1000);
    borrower.configure(&lender_id, &borrower_address, &true);

    lender.flash_loan(&borrower_address, &400);

    assert_eq!(lender.balance(&lender_id), 1000);
}

#[test]
fn test_malicious_borrower_vulnerable_flash_loan_succeeds() {
    let env = Env::default();
    let (lender, borrower, borrower_address, lender_id) = setup(&env);

    lender.mint(&lender_id, &1000);
    borrower.configure(&lender_id, &borrower_address, &false);

    lender.flash_loan(&borrower_address, &400);

    assert_eq!(lender.balance(&lender_id), 600);
}

#[test]
#[should_panic(expected = "Flash loan not repaid")]
fn test_malicious_borrower_secure_flash_loan_panics() {
    let env = Env::default();
    let (lender, borrower, borrower_address, lender_id) = setup(&env);

    lender.mint(&lender_id, &1000);
    borrower.configure(&lender_id, &borrower_address, &false);

    lender.flash_loan_secure(&borrower_address, &400);
}
