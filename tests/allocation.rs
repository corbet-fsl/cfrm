#![cfg(feature = "sqlite")]
mod common;
use cfrm::{allocation::{AllocationLedger, AllocationPolicy, AllocationRequest, policy_digest}, Error};
use common::{encoded,member_id,Fixture};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer,SigningKey};
use sha2::{Digest,Sha256};

fn policy() -> AllocationPolicy { AllocationPolicy { initial_credits: 2, periodic_credits: 1, period_seconds: 100, credit_cap: 3, max_authorization_seconds: 60, max_request_bytes: 1024 } }
fn request(f:&Fixture,key:&SigningKey,nonce:u8,now:u64)->AllocationRequest {
    let mut request=AllocationRequest { community_id:f.trust.community_id.clone(),member_id:member_id(5),chat_public_key:BASE64URL_NOPAD.encode(&key.verifying_key().to_bytes()),policy_digest:policy_digest(&policy()).unwrap(),nonce:encoded(nonce),blinded_request:BASE64URL_NOPAD.encode(&[nonce;384]),issued_at:now,expires_at:now+40,signature:String::new() };
    let hash=BASE64URL_NOPAD.encode(&Sha256::digest(BASE64URL_NOPAD.decode(request.blinded_request.as_bytes()).unwrap()));
    let bytes=serde_json::to_vec(&serde_json::json!(["cfrm.allocation.reserve.v1",request.community_id,request.member_id,request.chat_public_key,request.policy_digest,request.nonce,hash,request.issued_at,request.expires_at])).unwrap();
    request.signature=BASE64URL_NOPAD.encode(&key.sign(&bytes).to_bytes());request
}

#[test]
fn devices_share_one_durable_balance_and_identical_retry_does_not_debit() {
    let f=Fixture::new();let dir=tempfile::tempdir().unwrap();let path=dir.path().join("state.sqlite");
    let req=request(&f,&f.device,10,110);
    let first={let mut ledger=AllocationLedger::open(&path,f.trust.clone(),policy()).unwrap();ledger.reserve(&f.grant(5,&f.device),&f.authorize(5,&f.device),&req,||110).unwrap()};
    assert_eq!(first.remaining_credits,1);
    let second=SigningKey::from_bytes(&[7;32]);
    let mut ledger=AllocationLedger::open(&path,f.trust.clone(),policy()).unwrap();
    assert_eq!(ledger.reserve(&f.grant(5,&f.device),&f.authorize(5,&f.device),&req,||111).unwrap(),first);
    ledger.reserve(&f.grant(5,&second),&f.authorize(5,&second),&request(&f,&second,11,111),||111).unwrap();
    assert_eq!(ledger.balance(&member_id(5)).unwrap(),Some(0));
    assert_eq!(ledger.reserve(&f.grant(5,&f.device),&f.authorize(5,&f.device),&request(&f,&f.device,12,112),||112),Err(Error::NoAllowance));
}

#[test]
fn forged_or_expired_request_leaves_no_account_and_nonce_cannot_change_content() {
    let f=Fixture::new();let mut ledger=AllocationLedger::open(":memory:",f.trust.clone(),policy()).unwrap();
    let grant=f.grant(5,&f.device);let mut forged=request(&f,&f.device,10,110);forged.blinded_request=BASE64URL_NOPAD.encode(&[11;384]);
    assert_eq!(ledger.reserve(&grant,&f.authorize(5,&f.device),&forged,||110),Err(Error::Signature));
    assert_eq!(ledger.balance(&member_id(5)).unwrap(),None);
    let good=request(&f,&f.device,10,110);assert_eq!(ledger.reserve(&grant,&f.authorize(5,&f.device),&good,||150),Err(Error::Expired));
    ledger.reserve(&grant,&f.authorize(5,&f.device),&good,||110).unwrap();
    let changed=request(&f,&f.device,10,111);assert_eq!(ledger.reserve(&grant,&f.authorize(5,&f.device),&changed,||111),Err(Error::Replay));
    assert_eq!(ledger.balance(&member_id(5)).unwrap(),Some(1));
}

#[test]
fn periodic_allowance_cannot_be_reclaimed_on_reconnect_or_clock_rollback() {
    let f=Fixture::new();let dir=tempfile::tempdir().unwrap();let path=dir.path().join("state.sqlite");
    {let mut l=AllocationLedger::open(&path,f.trust.clone(),policy()).unwrap();l.reserve(&f.grant(5,&f.device),&f.authorize(5,&f.device),&request(&f,&f.device,10,110),||110).unwrap();l.reserve(&f.grant(5,&f.device),&f.authorize(5,&f.device),&request(&f,&f.device,11,210),||210).unwrap();assert_eq!(l.balance(&member_id(5)).unwrap(),Some(1));}
    let mut l=AllocationLedger::open(&path,f.trust.clone(),policy()).unwrap();
    assert_eq!(l.reserve(&f.grant(5,&f.device),&f.authorize(5,&f.device),&request(&f,&f.device,12,110),||110),Err(Error::ClockRollback));
    assert_eq!(l.balance(&member_id(5)).unwrap(),Some(1));
    let mut changed=policy();changed.initial_credits=3;
    assert!(matches!(AllocationLedger::open(&path,f.trust.clone(),changed),Err(Error::PolicyMismatch)));
}

#[test]
fn resolve_answer_or_close_fails_closed_without_proof_backend() {
    let f=Fixture::new();let mut l=AllocationLedger::open(":memory:",f.trust.clone(),policy()).unwrap();
    l.reserve(&f.grant(5,&f.device),&f.authorize(5,&f.device),&request(&f,&f.device,10,110),||110).unwrap();
    for forged in [b"answered".as_slice(),b"closedForever".as_slice(),b"".as_slice()] {assert_eq!(l.resolve_private(forged),Err(Error::UnsupportedCapability));}
    assert_eq!(l.balance(&member_id(5)).unwrap(),Some(1));
}

#[test]
fn simultaneous_devices_cannot_exceed_identity_allowance() {
    let f=Fixture::new();let dir=tempfile::tempdir().unwrap();let path=dir.path().join("state.sqlite");
    let mut workers=Vec::new();let barrier=std::sync::Arc::new(std::sync::Barrier::new(3));
    for seed in [10,11,12] {
        let mut ledger=AllocationLedger::open(&path,f.trust.clone(),policy()).unwrap();
        let ready=barrier.clone();
        workers.push(std::thread::spawn(move || {
            let f=Fixture::new();let key=SigningKey::from_bytes(&[seed;32]);
            let grant=f.grant(5,&key);let authorization=f.authorize(5,&key);let request=request(&f,&key,seed,110);
            ready.wait();ledger.reserve(&grant,&authorization,&request,||110)
        }));
    }
    let results:Vec<_>=workers.into_iter().map(|worker|worker.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|result|result.is_ok()).count(),2);
    assert_eq!(results.iter().filter(|result|matches!(result,Err(Error::NoAllowance))).count(),1);
    let ledger=AllocationLedger::open(&path,f.trust,policy()).unwrap();
    assert_eq!(ledger.balance(&member_id(5)).unwrap(),Some(0));
}

#[test]
fn expiry_inside_transaction_cannot_create_an_account_or_debit() {
    let f=Fixture::new();let mut ledger=AllocationLedger::open(":memory:",f.trust.clone(),policy()).unwrap();
    let calls=std::cell::Cell::new(0);
    let clock=|| {let call=calls.get();calls.set(call+1);if call==0 {110} else {150}};
    assert_eq!(ledger.reserve(&f.grant(5,&f.device),&f.authorize(5,&f.device),&request(&f,&f.device,10,110),clock),Err(Error::Expired));
    assert_eq!(ledger.balance(&member_id(5)).unwrap(),None);
}

#[test]
fn copied_eligibility_does_not_authorize_a_member_owned_budget() {
    let f=Fixture::new();let attacker=SigningKey::from_bytes(&[8;32]);
    let mut forged=f.authorize(8,&attacker);forged.member_id=member_id(5);
    let mut ledger=AllocationLedger::open(":memory:",f.trust.clone(),policy()).unwrap();
    assert_eq!(ledger.reserve(&f.grant(5,&attacker),&forged,&request(&f,&attacker,10,110),||110),Err(Error::Admission));
    assert_eq!(ledger.balance(&member_id(5)).unwrap(),None);
}

#[test]
fn invalid_persisted_sql_integers_fail_closed() {
    for mutation in [
        "UPDATE cfrm_allocation_config SET clock_floor=-1",
        "UPDATE cfrm_allocation_config SET clock_floor=9007199254740992",
        "UPDATE cfrm_allocation_members SET credits=9007199254740992",
        "UPDATE cfrm_allocation_members SET credits=4",
        "UPDATE cfrm_allocation_members SET last_period=-1",
    ] {
        let f=Fixture::new(); let dir=tempfile::tempdir().unwrap(); let path=dir.path().join("state.sqlite");
        let mut ledger=AllocationLedger::open(&path,f.trust.clone(),policy()).unwrap();
        ledger.reserve(&f.grant(5,&f.device),&f.authorize(5,&f.device),&request(&f,&f.device,10,110),||110).unwrap();
        rusqlite::Connection::open(&path).unwrap().execute(mutation,[]).unwrap();
        assert_eq!(ledger.reserve(&f.grant(5,&f.device),&f.authorize(5,&f.device),&request(&f,&f.device,11,110),||110),Err(Error::Storage));
    }
}
