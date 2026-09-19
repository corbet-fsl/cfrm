#![cfg(all(feature = "permit-issuer", not(target_arch = "wasm32")))]
mod common;
use cfrm::{
    allocation::{policy_digest, AllocationLedger, AllocationPolicy, AllocationRequest},
    key_access::*,
    permit_issuer::PermitIssuer,
    permits::{Permit, PermitEpoch, PreparedPermit},
    Error,
};
use common::{encoded, member_id, Fixture};
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::{Signer, SigningKey};
use openssl::rsa::Rsa;
use std::{path::Path, sync::OnceLock};

fn private_key() -> &'static [u8] {
    static KEY: OnceLock<Vec<u8>> = OnceLock::new();
    KEY.get_or_init(|| Rsa::generate(3072).unwrap().private_key_to_der().unwrap())
}
fn redemption_key() -> SigningKey {
    SigningKey::from_bytes(&[61; 32])
}
fn epoch() -> PermitEpoch {
    PermitEpoch {
        community_id: "community.example".into(),
        epoch_id: "cfrm.key-access.v1/test".into(),
        valid_from: 100,
        issue_until: 400,
        expires_at: 500,
        public_key_der: B64.encode(
            &Rsa::private_key_from_der(private_key())
                .unwrap()
                .public_key_to_der()
                .unwrap(),
        ),
        redemption_public_key: B64.encode(&redemption_key().verifying_key().to_bytes()),
    }
}
fn policy() -> KeyAccessPolicy {
    KeyAccessPolicy {
        maximum_per_member: 1,
        maximum_members: 2,
        max_authorization_seconds: 60,
    }
}
fn open(path: &Path, f: &Fixture) -> KeyAccessIssuer {
    KeyAccessIssuer::open(path, f.trust.clone(), epoch(), policy(), private_key()).unwrap()
}
fn request(
    member: u8,
    key: &SigningKey,
    prepared: &PreparedPermit,
    id: u8,
) -> KeyAccessIssueRequest {
    let mut request = KeyAccessIssueRequest {
        community_id: epoch().community_id,
        member_id: member_id(member),
        chat_public_key: B64.encode(&key.verifying_key().to_bytes()),
        context_id: epoch().context_id().unwrap(),
        request_id: encoded(id),
        blinded_request: B64.encode(&prepared.issuance_request()),
        issued_at: 110,
        expires_at: 150,
        signature: String::new(),
    };
    request.signature = B64.encode(
        &key.sign(&key_access_issue_bytes(&request).unwrap())
            .to_bytes(),
    );
    request
}
fn permit(path: &Path, f: &Fixture) -> Permit {
    let prepared = PreparedPermit::new(&epoch(), 110).unwrap();
    let response = open(path, f)
        .issue(
            &f.grant(5, &f.device),
            &f.authorize(5, &f.device),
            &request(5, &f.device, &prepared, 7),
            || 110,
        )
        .unwrap();
    prepared.finalize(&response.blind_signature, 110).unwrap()
}

#[test]
fn real_blind_resource_quota_is_per_member_across_devices_with_exact_retry_and_no_account_ledger() {
    let f = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("quota");
    let prepared = PreparedPermit::new(&epoch(), 110).unwrap();
    let original = request(5, &f.device, &prepared, 8);
    let first = open(&path, &f)
        .issue(
            &f.grant(5, &f.device),
            &f.authorize(5, &f.device),
            &original,
            || 110,
        )
        .unwrap();
    let other = SigningKey::from_bytes(&[42; 32]);
    let mut issuer = open(&path, &f);
    let retry = issuer
        .issue(
            &f.grant(5, &other),
            &f.authorize(5, &other),
            &original,
            || 160,
        )
        .unwrap();
    assert_eq!(first, retry);
    prepared.finalize(&retry.blind_signature, 160).unwrap();
    let second = PreparedPermit::new(&epoch(), 160).unwrap();
    let mut next = request(5, &other, &second, 9);
    next.issued_at = 160;
    next.expires_at = 200;
    next.signature = B64.encode(
        &other
            .sign(&key_access_issue_bytes(&next).unwrap())
            .to_bytes(),
    );
    assert!(matches!(
        issuer.issue(&f.grant(5, &other), &f.authorize(5, &other), &next, || 160),
        Err(Error::Capacity)
    ));
    drop(issuer);
    let db = rusqlite::Connection::open(&path).unwrap();
    let tables:i64=db.query_row("SELECT count(*) FROM sqlite_master WHERE name LIKE 'cfrm_accounts%' OR name LIKE 'cfrm_allocations%'",[],|r|r.get(0)).unwrap();
    assert_eq!(tables, 0);
    let count: i64 = db
        .query_row("SELECT issued FROM cfrm_key_access_members", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn anonymous_stamp_binds_one_fresh_challenge_and_retries_without_another_spend() {
    let f = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let token = permit(&dir.path().join("quota"), &f);
    let request = KeyAccessRedemption {
        permit: token,
        challenge_digest: encoded(11),
        expires_at: 200,
        claim: encoded(12),
    };
    let mut redeemer =
        KeyAccessRedeemer::open(dir.path().join("spent"), epoch(), redemption_key()).unwrap();
    let stamp = redeemer.redeem(&request, || 110).unwrap();
    verify_key_access_stamp(&epoch(), &stamp, &request.challenge_digest, 200, 110).unwrap();
    assert_eq!(redeemer.redeem(&request, || 111).unwrap(), stamp);
    let mut other = request.clone();
    other.challenge_digest = encoded(13);
    assert!(matches!(
        redeemer.redeem(&other, || 112),
        Err(Error::Replay)
    ));
    assert!(verify_key_access_stamp(&epoch(), &stamp, &other.challenge_digest, 200, 112).is_err());
    assert!(
        verify_key_access_stamp(&epoch(), &stamp, &request.challenge_digest, 201, 112).is_err()
    );
    assert!(
        verify_key_access_stamp(&epoch(), &stamp, &request.challenge_digest, 200, 200).is_err()
    );
    let mut intro = epoch();
    intro.epoch_id = "introductions".into();
    assert!(matches!(
        verify_key_access_stamp(&intro, &stamp, &request.challenge_digest, 200, 112),
        Err(Error::PolicyMismatch)
    ));
    let db = rusqlite::Connection::open(dir.path().join("spent")).unwrap();
    let columns: Vec<String> = db
        .prepare("PRAGMA table_info(cfrm_redemptions)")
        .unwrap()
        .query_map([], |r| r.get(1))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(columns, vec!["token", "claim", "commitment", "stamp"]);
    // Actual Rust-issued RFC9474 ticket -> Rust redemption stamp -> browser adapter.
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let prepared = PreparedPermit::new(&epoch(), 110).unwrap();
    let issue_request = self::request(5, &f.device, &prepared, 14);
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("test/key-access-interop.mjs");
    let mut child = Command::new("node")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let input = serde_json::json!({"epoch":epoch(),"now":110,"stamp":stamp,"challengeDigest":request.challenge_digest,
        "expiresAt":request.expires_at,"issueRequest":issue_request});
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&input).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let checked: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(checked["ok"], true);
    assert_eq!(checked["changedChallengeAccepted"], false);
    assert_eq!(
        checked["issueBytes"],
        B64.encode(&key_access_issue_bytes(&issue_request).unwrap())
    );
}

#[test]
fn expiry_during_signing_rolls_back_quota_and_pruning_cannot_revive_the_epoch() {
    use std::cell::Cell;
    let f = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("quota");
    let prepared = PreparedPermit::new(&epoch(), 110).unwrap();
    let request = request(5, &f.device, &prepared, 7);
    let mut issuer = open(&path, &f);
    let calls = Cell::new(0);
    assert!(matches!(
        issuer.issue(
            &f.grant(5, &f.device),
            &f.authorize(5, &f.device),
            &request,
            || {
                let n = calls.get();
                calls.set(n + 1);
                if n < 2 {
                    110
                } else {
                    150
                }
            }
        ),
        Err(Error::Expired)
    ));
    let issued = issuer
        .issue(
            &f.grant(5, &f.device),
            &f.authorize(5, &f.device),
            &request,
            || 110,
        )
        .unwrap();
    let token = prepared.finalize(&issued.blind_signature, 110).unwrap();
    let mut redeemer =
        KeyAccessRedeemer::open(dir.path().join("spent"), epoch(), redemption_key()).unwrap();
    let redemption = KeyAccessRedemption {
        permit: token,
        challenge_digest: encoded(9),
        expires_at: 200,
        claim: encoded(10),
    };
    let ticks = Cell::new(0);
    assert!(redeemer
        .redeem(&redemption, || {
            let n = ticks.get();
            ticks.set(n + 1);
            if n < 3 {
                110
            } else {
                200
            }
        })
        .is_err());
    redeemer.redeem(&redemption, || 110).unwrap();
    issuer.prune_expired(500).unwrap();
    redeemer.prune_expired(500).unwrap();
    assert!(issuer
        .issue(
            &f.grant(5, &f.device),
            &f.authorize(5, &f.device),
            &request,
            || 110
        )
        .is_err());
    assert!(redeemer.redeem(&redemption, || 110).is_err());
    let db = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM cfrm_key_access_issues", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM cfrm_permit_epochs", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn key_registry_and_namespace_prevent_cross_purpose_issuance_in_shared_database() {
    let f = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("quota");
    let _issuer = open(&path, &f);
    let mut another = epoch();
    another.epoch_id = "cfrm.key-access.v1/another".into();
    assert!(matches!(
        KeyAccessIssuer::open(&path, f.trust.clone(), another, policy(), private_key()),
        Err(Error::PolicyMismatch)
    ));
    let allocation_policy = AllocationPolicy {
        initial_credits: 2,
        periodic_credits: 0,
        period_seconds: 100,
        credit_cap: 2,
        max_authorization_seconds: 60,
        max_request_bytes: 416,
    };
    let mut ledger =
        AllocationLedger::open(&path, f.trust.clone(), allocation_policy.clone()).unwrap();
    let prepared = PreparedPermit::new(&epoch(), 110).unwrap();
    let mut request = AllocationRequest {
        community_id: epoch().community_id,
        member_id: member_id(5),
        chat_public_key: B64.encode(&f.device.verifying_key().to_bytes()),
        policy_digest: policy_digest(&allocation_policy).unwrap(),
        nonce: encoded(3),
        blinded_request: B64.encode(&prepared.issuance_request()),
        issued_at: 110,
        expires_at: 150,
        signature: String::new(),
    };
    request.signature = B64.encode(
        &f.device
            .sign(&cfrm::allocation::allocation_bytes(&request).unwrap())
            .to_bytes(),
    );
    assert!(matches!(
        PermitIssuer::from_pkcs1_der(&epoch(), private_key())
            .unwrap()
            .issue(
                &mut ledger,
                &f.grant(5, &f.device),
                &f.authorize(5, &f.device),
                &request,
                || 110
            ),
        Err(Error::PolicyMismatch)
    ));
    assert_eq!(ledger.balance(&member_id(5)).unwrap(), None);
    let mut intro = epoch();
    intro.epoch_id = "introductions".into();
    let intro_prepared = PreparedPermit::new(&intro, 110).unwrap();
    request.blinded_request = B64.encode(&intro_prepared.issuance_request());
    request.signature = B64.encode(
        &f.device
            .sign(&cfrm::allocation::allocation_bytes(&request).unwrap())
            .to_bytes(),
    );
    assert!(matches!(
        PermitIssuer::from_pkcs1_der(&intro, private_key())
            .unwrap()
            .issue(
                &mut ledger,
                &f.grant(5, &f.device),
                &f.authorize(5, &f.device),
                &request,
                || 110
            ),
        Err(Error::PolicyMismatch)
    ));
}

#[test]
fn independent_connections_cannot_race_past_member_quota_or_spend_one_token_twice() {
    use std::sync::{Arc, Barrier};
    let f = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("quota");
    drop(open(&path, &f));
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|index| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let f = Fixture::new();
                let mut issuer = open(&path, &f);
                let prepared = PreparedPermit::new(&epoch(), 110).unwrap();
                let request = request(5, &f.device, &prepared, 20 + index);
                barrier.wait();
                issuer
                    .issue(
                        &f.grant(5, &f.device),
                        &f.authorize(5, &f.device),
                        &request,
                        || 110,
                    )
                    .map(|response| prepared.finalize(&response.blind_signature, 110).unwrap())
            })
        })
        .collect();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(Error::Capacity)))
            .count(),
        1
    );
    let token = results.into_iter().find_map(Result::ok).unwrap();
    let spent = dir.path().join("spent");
    drop(KeyAccessRedeemer::open(&spent, epoch(), redemption_key()).unwrap());
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|index| {
            let path = spent.clone();
            let barrier = barrier.clone();
            let token = token.clone();
            std::thread::spawn(move || {
                let mut redeemer =
                    KeyAccessRedeemer::open(path, epoch(), redemption_key()).unwrap();
                let request = KeyAccessRedemption {
                    permit: token,
                    challenge_digest: encoded(31 + index),
                    expires_at: 200,
                    claim: encoded(41 + index),
                };
                barrier.wait();
                redeemer.redeem(&request, || 110)
            })
        })
        .collect();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(Error::Replay)))
            .count(),
        1
    );
}
