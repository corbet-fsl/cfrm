#![cfg(all(feature = "permit-issuer", not(target_arch = "wasm32")))]
mod common;
use cfrm::{allocation::{AllocationLedger, AllocationPolicy, AllocationRequest, policy_digest}, permit_issuer::{PermitIssuer, PermitRedeemer}, permits::{Permit, PermitEpoch, PreparedPermit, RecipientClaim, ISSUANCE_REQUEST_BYTES}, Error};
use common::{encoded, member_id, Fixture};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer, SigningKey};
use openssl::rsa::Rsa;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Barrier, OnceLock};

fn key_der() -> &'static [u8] {
    static KEY: OnceLock<Vec<u8>> = OnceLock::new();
    KEY.get_or_init(|| Rsa::generate(3072).unwrap().private_key_to_der().unwrap())
}
fn stamp_key() -> SigningKey { SigningKey::from_bytes(&[71; 32]) }
fn epoch() -> PermitEpoch {
    PermitEpoch { community_id: "community.example".into(), epoch_id: "test-epoch".into(), valid_from: 100, issue_until: 400, expires_at: 500, public_key_der: BASE64URL_NOPAD.encode(&Rsa::private_key_from_der(key_der()).unwrap().public_key_to_der().unwrap()), redemption_public_key: BASE64URL_NOPAD.encode(&stamp_key().verifying_key().to_bytes()) }
}
fn policy() -> AllocationPolicy {
    AllocationPolicy { initial_credits: 2, periodic_credits: 0, period_seconds: 100, credit_cap: 2, max_authorization_seconds: 60, max_request_bytes: ISSUANCE_REQUEST_BYTES }
}
fn request(f: &Fixture, key: &SigningKey, payload: &[u8], nonce: u8) -> AllocationRequest {
    let mut request = AllocationRequest { community_id: f.trust.community_id.clone(), member_id: member_id(5), chat_public_key: BASE64URL_NOPAD.encode(&key.verifying_key().to_bytes()), policy_digest: policy_digest(&policy()).unwrap(), nonce: encoded(nonce), blinded_request: BASE64URL_NOPAD.encode(payload), issued_at: 110, expires_at: 150, signature: String::new() };
    let bytes = serde_json::to_vec(&serde_json::json!(["cfrm.allocation.reserve.v1", request.community_id, request.member_id, request.chat_public_key, request.policy_digest, request.nonce, BASE64URL_NOPAD.encode(&Sha256::digest(payload)), request.issued_at, request.expires_at])).unwrap();
    request.signature = BASE64URL_NOPAD.encode(&key.sign(&bytes).to_bytes()); request
}
fn issue_permit(f: &Fixture, ledger: &mut AllocationLedger, nonce: u8) -> Permit {
    let epoch = epoch(); let prepared = PreparedPermit::new(&epoch, 110).unwrap();
    let request = request(f, &f.device, &prepared.issuance_request(), nonce);
    let response = PermitIssuer::from_pkcs1_der(&epoch, key_der()).unwrap().issue(ledger, &f.grant(5, &f.device), &f.authorize(5, &f.device), &request, || 110).unwrap();
    prepared.finalize(&response.blind_signature, 110).unwrap()
}

#[test]
fn real_blind_issue_debit_recovery_and_private_recipient_redemption() {
    let f = Fixture::new(); let epoch = epoch(); let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("allowance.sqlite"); let prepared = PreparedPermit::new(&epoch, 110).unwrap();
    let request = request(&f, &f.device, &prepared.issuance_request(), 10);
    let issuer = PermitIssuer::from_pkcs1_der(&epoch, key_der()).unwrap();
    let first = {
        let mut ledger = AllocationLedger::open(&path, f.trust.clone(), policy()).unwrap();
        issuer.issue(&mut ledger, &f.grant(5, &f.device), &f.authorize(5, &f.device), &request, || 110).unwrap()
    };
    let mut ledger = AllocationLedger::open(&path, f.trust.clone(), policy()).unwrap();
    assert_eq!(issuer.issue(&mut ledger, &f.grant(5, &f.device), &f.authorize(5, &f.device), &request, || 111).unwrap(), first);
    assert_eq!(ledger.balance(&member_id(5)).unwrap(), Some(1));
    let checkpoint = prepared.export_private();
    let restored = PreparedPermit::restore_private(&epoch, &checkpoint).unwrap();
    assert_eq!(prepared.issuance_request(), restored.issuance_request());
    let permit = restored.finalize(&first.blind_signature, 160).unwrap();
    permit.verify(&epoch, 160).unwrap();
    let claim = RecipientClaim::new(&epoch, permit, &member_id(5), &member_id(6), [4; 32], [8; 32], 160).unwrap();
    let wire = serde_json::to_string(&claim.request).unwrap();
    assert!(!wire.contains(&member_id(5))); assert!(!wire.contains(&member_id(6)));
    let path = dir.path().join("spent.sqlite");
    let stamp = { let mut redeemer = PermitRedeemer::open(&path, &epoch, stamp_key()).unwrap(); redeemer.redeem(&claim.request, || 160).unwrap() };
    let mut redeemer = PermitRedeemer::open(&path, &epoch, stamp_key()).unwrap();
    assert_eq!(redeemer.redeem(&claim.request, || 161).unwrap(), stamp);
    claim.verify_stamp(&epoch, &stamp, 161).unwrap();
    let mut substituted = claim.clone(); substituted.binding.recipient_id = member_id(7);
    assert_eq!(substituted.verify_stamp(&epoch, &stamp, 161), Err(Error::Admission));
    let mut changed_challenge = claim.clone(); changed_challenge.binding.challenge = encoded(9);
    assert_eq!(changed_challenge.verify_stamp(&epoch, &stamp, 161), Err(Error::Admission));
    let mut changed_intro = claim.clone(); changed_intro.binding.introduction_id = encoded(9);
    assert_eq!(changed_intro.verify_stamp(&epoch, &stamp, 161), Err(Error::Admission));
    let mut forged_stamp = stamp.clone(); forged_stamp.signature = BASE64URL_NOPAD.encode(&[1; 64]);
    assert_eq!(claim.verify_stamp(&epoch, &forged_stamp, 161), Err(Error::Signature));
}

#[test]
fn simultaneous_devices_share_allowance_and_invalid_rsa_input_never_debits() {
    let f = Fixture::new(); let epoch = epoch(); let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("allowance.sqlite");
    let mut ledger = AllocationLedger::open(&path, f.trust.clone(), policy()).unwrap();
    let mut invalid = vec![0; ISSUANCE_REQUEST_BYTES]; invalid[..32].copy_from_slice(&BASE64URL_NOPAD.decode(epoch.context_id().unwrap().as_bytes()).unwrap());
    let issuer = PermitIssuer::from_pkcs1_der(&epoch, key_der()).unwrap();
    assert!(issuer.issue(&mut ledger, &f.grant(5, &f.device), &f.authorize(5, &f.device), &request(&f, &f.device, &invalid, 9), || 110).is_err());
    assert_eq!(ledger.balance(&member_id(5)).unwrap(), None);
    let ready = Arc::new(Barrier::new(3)); let mut workers = Vec::new();
    for seed in [10, 11, 12] {
        let mut ledger = AllocationLedger::open(&path, f.trust.clone(), policy()).unwrap();
        let ready = ready.clone(); let epoch = epoch.clone();
        workers.push(std::thread::spawn(move || {
            let f = Fixture::new(); let key = SigningKey::from_bytes(&[seed; 32]);
            let prepared = PreparedPermit::new(&epoch, 110).unwrap(); let request = request(&f, &key, &prepared.issuance_request(), seed);
            let issuer = PermitIssuer::from_pkcs1_der(&epoch, key_der()).unwrap();
            ready.wait(); let response = issuer.issue(&mut ledger, &f.grant(5, &key), &f.authorize(5, &key), &request, || 110)?;
            prepared.finalize(&response.blind_signature, 110)
        }));
    }
    let results: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 2);
    assert_eq!(results.iter().filter(|result| matches!(result, Err(Error::NoAllowance))).count(), 1);
    assert_eq!(ledger.balance(&member_id(5)).unwrap(), Some(0));
}

#[test]
fn copied_bearer_permit_can_win_only_one_recipient_claim_even_concurrently() {
    let f = Fixture::new(); let epoch = epoch();
    let mut ledger = AllocationLedger::open(":memory:", f.trust.clone(), policy()).unwrap();
    let permit = issue_permit(&f, &mut ledger, 10);
    // This deliberately allows transfer: aggregate bearer credits do not prove
    // the sender is the member whose account paid for the blind issuance.
    let first = RecipientClaim::new(&epoch, permit.clone(), &member_id(8), &member_id(6), [4; 32], [8; 32], 120).unwrap();
    let second = RecipientClaim::new(&epoch, permit, &member_id(9), &member_id(7), [5; 32], [9; 32], 120).unwrap();
    let dir = tempfile::tempdir().unwrap(); let path = dir.path().join("spent.sqlite");
    let ready = Arc::new(Barrier::new(2)); let mut workers = Vec::new();
    for claim in [first, second] {
        let mut redeemer = PermitRedeemer::open(&path, &epoch, stamp_key()).unwrap();
        let ready = ready.clone();
        workers.push(std::thread::spawn(move || { ready.wait(); redeemer.redeem(&claim.request, || 120) }));
    }
    let results: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| matches!(result, Err(Error::Replay))).count(), 1);
}

#[test]
fn wrong_context_mutation_common_expiry_and_key_reuse_are_rejected() {
    let f = Fixture::new(); let epoch = epoch(); let issuer = PermitIssuer::from_pkcs1_der(&epoch, key_der()).unwrap();
    let mut ledger = AllocationLedger::open(":memory:", f.trust.clone(), policy()).unwrap();
    let permit = issue_permit(&f, &mut ledger, 10);
    let mut forged = permit.clone(); forged.serial = encoded(4);
    assert_eq!(forged.verify(&epoch, 120), Err(Error::Signature));
    assert_eq!(permit.verify(&epoch, 500), Err(Error::Expired));
    let mut other = epoch.clone(); other.epoch_id = "other-epoch".into();
    assert_eq!(permit.verify(&other, 120), Err(Error::Admission));
    let prepared = PreparedPermit::new(&other, 110).unwrap();
    let request = request(&f, &f.device, &prepared.issuance_request(), 11);
    assert_eq!(issuer.issue(&mut ledger, &f.grant(5, &f.device), &f.authorize(5, &f.device), &request, || 110), Err(Error::Admission));
    let reused = PermitIssuer::from_pkcs1_der(&other, key_der()).unwrap();
    assert_eq!(reused.issue(&mut ledger, &f.grant(5, &f.device), &f.authorize(5, &f.device), &request, || 110), Err(Error::PolicyMismatch));
    assert_eq!(ledger.balance(&member_id(5)).unwrap(), Some(1));
    let claim = RecipientClaim::new(&epoch, permit, &member_id(5), &member_id(6), [4; 32], [8; 32], 120).unwrap();
    let mut redeemer = PermitRedeemer::open(":memory:", &epoch, stamp_key()).unwrap();
    let calls = std::cell::Cell::new(0); let clock = || { let call = calls.get(); calls.set(call + 1); if call == 0 { 120 } else { 500 } };
    assert_eq!(redeemer.redeem(&claim.request, clock), Err(Error::Expired));
    // Expiry failure did not spend the permit or advance the database clock.
    redeemer.redeem(&claim.request, || 120).unwrap();
    assert_eq!(redeemer.redeem(&claim.request, || 119), Err(Error::ClockRollback));
    assert_eq!(redeemer.redeem(&claim.request, || 500), Err(Error::Expired));
}

#[test]
fn bare_reservations_cannot_be_upgraded_to_signatures_and_bad_reply_stays_invalid() {
    let f = Fixture::new(); let epoch = epoch(); let issuer = PermitIssuer::from_pkcs1_der(&epoch, key_der()).unwrap();
    let mut ledger = AllocationLedger::open(":memory:", f.trust.clone(), policy()).unwrap();
    let prepared = PreparedPermit::new(&epoch, 110).unwrap(); let request = request(&f, &f.device, &prepared.issuance_request(), 10);
    ledger.reserve(&f.grant(5, &f.device), &f.authorize(5, &f.device), &request, || 110).unwrap();
    assert_eq!(issuer.issue(&mut ledger, &f.grant(5, &f.device), &f.authorize(5, &f.device), &request, || 110), Err(Error::Replay));
    assert_eq!(ledger.balance(&member_id(5)).unwrap(), Some(1));
    assert!(matches!(prepared.finalize(&[1; 384], 110), Err(Error::Signature)));
}

#[test]
fn expiry_after_private_signing_rolls_back_signature_debit_and_epoch_registration() {
    let f = Fixture::new(); let epoch = epoch(); let issuer = PermitIssuer::from_pkcs1_der(&epoch, key_der()).unwrap();
    let mut ledger = AllocationLedger::open(":memory:", f.trust.clone(), policy()).unwrap();
    let prepared = PreparedPermit::new(&epoch, 110).unwrap(); let request = request(&f, &f.device, &prepared.issuance_request(), 10);
    let calls = std::cell::Cell::new(0); let clock = || { let call = calls.get(); calls.set(call + 1); if call < 2 { 110 } else { 150 } };
    assert_eq!(issuer.issue(&mut ledger, &f.grant(5, &f.device), &f.authorize(5, &f.device), &request, clock), Err(Error::Expired));
    assert_eq!(ledger.balance(&member_id(5)).unwrap(), None);
    // Nothing escaped on the failed attempt. Its nonce remains available.
    let response = issuer.issue(&mut ledger, &f.grant(5, &f.device), &f.authorize(5, &f.device), &request, || 110).unwrap();
    prepared.finalize(&response.blind_signature, 110).unwrap();
    assert_eq!(ledger.balance(&member_id(5)).unwrap(), Some(1));
}
