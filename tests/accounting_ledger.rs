#![cfg(feature = "sqlite")]
//! These are storage/authorization tests with an explicitly synthetic verifier.
//! Real circuit acceptance is exercised separately by the browser proof suite.

mod common;
use cfrm::{accounting::*, accounting_ledger::*, Error};
use common::Fixture;
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    path::Path,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc,
    },
    time::Duration,
};

#[derive(Clone, Default)]
struct StorageOnlyVerifier {
    calls: Arc<AtomicUsize>,
    reject: bool,
}
impl AccountProofVerifier for StorageOnlyVerifier {
    fn scope(&self) -> AccountProofScope {
        AccountProofScope {
            circuit_digest: [41; 32],
            verifying_key_digest: [42; 32],
        }
    }
    fn verify(&self, _: &AccountStatement, proof: &[u8]) -> Result<(), Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.reject || proof != [1, 2, 3] {
            Err(Error::CryptoProvider)
        } else {
            Ok(())
        }
    }
}

struct BlockedVerifier {
    inner: StorageOnlyVerifier,
    entered: Sender<()>,
    release: Receiver<()>,
}

impl AccountProofVerifier for BlockedVerifier {
    fn scope(&self) -> AccountProofScope {
        self.inner.scope()
    }
    fn verify(&self, statement: &AccountStatement, proof: &[u8]) -> Result<(), Error> {
        self.inner.verify(statement, proof)?;
        self.entered.send(()).map_err(|_| Error::CryptoProvider)?;
        self.release
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| Error::CryptoProvider)
    }
}

fn blocked_verifier() -> (BlockedVerifier, Receiver<()>, Sender<()>) {
    let (entered, observed) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    (
        BlockedVerifier {
            inner: StorageOnlyVerifier::default(),
            entered,
            release: resume,
        },
        observed,
        release,
    )
}

fn fr(n: u8) -> [u8; 32] {
    let mut value = [0; 32];
    value[31] = n;
    value
}
fn policy() -> AccountLedgerPolicy {
    // Test values only. Library consumers must choose their own complete policy.
    AccountLedgerPolicy {
        account: AccountPolicy {
            initial_credit: 3,
            maximum_available: 4,
            outgoing_reservation: 1,
            incoming_reservation: 1,
            policy_revision: 1,
            policy_valid_from: 1,
            policy_valid_until: 2000,
            newcomer_period: 100,
            rate_window: 1000,
            newcomer_admissions: 2,
            maximum_admissions: 4,
            refill_period: 100,
            refill_units: 1,
            abandon_after: 1000,
        },
        max_authorization_seconds: 100,
        max_proof_bytes: 20000,
        checkpoint_period_seconds: 1000,
    }
}
fn open<V: AccountProofVerifier>(path: &Path, fixture: &Fixture, verifier: V) -> AccountLedger<V> {
    AccountLedger::open(
        path,
        fixture.trust.clone(),
        policy(),
        verifier,
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap()
}
fn sign(request: &mut AccountRequest, key: &SigningKey) {
    request.signature = B64.encode(
        &key.sign(&account_request_bytes(request).unwrap())
            .to_bytes(),
    );
}

#[cfg(feature = "turso")]
#[test]
#[ignore = "requires the isolated official sqld contract lane"]
fn remote_account_frontier_retry_restart_and_rejected_successor() {
    let f = Fixture::new();
    let open_remote = || {
        AccountLedger::open_remote(
            common::remote_config(),
            f.trust.clone(),
            policy(),
            StorageOnlyVerifier::default(),
            SigningKey::from_bytes(&[9; 32]),
        )
        .unwrap()
    };
    let mut ledger = open_remote();
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    let grant = f.grant(7, &f.device);
    let authorization = f.authorize(7, &f.device);
    let first = genesis(&f);
    let accepted = ledger
        .apply(&grant, &authorization, &first, || 120)
        .unwrap();
    drop(ledger);
    let mut ledger = open_remote();
    assert_eq!(
        ledger
            .apply(&grant, &authorization, &first, || 121)
            .unwrap(),
        accepted
    );
    let next = successor(&first, &f, 11);
    let mut rejected = next.clone();
    rejected.proof = vec![4, 5, 6];
    sign(&mut rejected, &f.device);
    assert_eq!(
        ledger.apply(&grant, &authorization, &rejected, || 130),
        Err(Error::CryptoProvider)
    );
    let winner = ledger.apply(&grant, &authorization, &next, || 130).unwrap();
    let competing = successor(&first, &f, 12);
    assert!(ledger
        .apply(&grant, &authorization, &competing, || 131)
        .is_err());
    drop(ledger);
    assert_eq!(
        open_remote()
            .apply(&grant, &authorization, &next, || 132)
            .unwrap(),
        winner
    );
}
fn genesis(fixture: &Fixture) -> AccountRequest {
    let community: [u8; 32] = Sha256::digest(fixture.trust.community_id.as_bytes()).into();
    let owner = B64
        .decode(common::member_id(7).as_bytes())
        .unwrap()
        .try_into()
        .unwrap();
    let account = policy().account;
    let mut request = AccountRequest {
        statement: AccountStatement {
            protocol_version: 2,
            community,
            owner,
            policy_digest: account.digest(&community).unwrap(),
            enrollment_root: fr(8),
            now: 110,
            valid_until: account.proof_valid_until(110).unwrap(),
            genesis: true,
            previous_version: 0,
            next_version: 0,
            previous_state: fr(0),
            next_state: fr(1),
            settlement_marker: fr(0),
            policy: account,
        },
        request_id: [10; 32],
        proof_scope: StorageOnlyVerifier::default().scope(),
        chat_public_key: B64.encode(&fixture.device.verifying_key().to_bytes()),
        issued_at: 110,
        expires_at: 180,
        proof: vec![1, 2, 3],
        signature: String::new(),
    };
    sign(&mut request, &fixture.device);
    request
}
fn successor(prior: &AccountRequest, fixture: &Fixture, id: u8) -> AccountRequest {
    let mut request = prior.clone();
    request.statement.genesis = false;
    request.statement.previous_version = prior.statement.next_version;
    request.statement.next_version = prior.statement.next_version + 1;
    request.statement.previous_state = prior.statement.next_state;
    request.statement.next_state = fr(prior.statement.next_state[31] + 1);
    request.statement.settlement_marker = fr(15);
    request.request_id = [id; 32];
    sign(&mut request, &fixture.device);
    request
}

#[test]
fn rejected_proof_cannot_register_and_genesis_is_lifetime_unique_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let f = Fixture::new();
    let g = f.grant(7, &f.device);
    let a = f.authorize(7, &f.device);
    let request = genesis(&f);
    let mut ledger = open(
        &path,
        &f,
        StorageOnlyVerifier {
            reject: true,
            ..Default::default()
        },
    );
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    assert_eq!(
        ledger.apply(&g, &a, &request, || 120),
        Err(Error::CryptoProvider)
    );
    drop(ledger);
    let mut ledger = open(&path, &f, StorageOnlyVerifier::default());
    let accepted = ledger.apply(&g, &a, &request, || 120).unwrap();
    verify_account_acceptance(
        &accepted,
        &SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    drop(ledger);
    let mut ledger = open(&path, &f, StorageOnlyVerifier::default());
    let mut second = request.clone();
    second.request_id = [11; 32];
    sign(&mut second, &f.device);
    assert_eq!(ledger.apply(&g, &a, &second, || 130), Err(Error::Replay));
    assert_eq!(ledger.apply(&g, &a, &request, || 200).unwrap(), accepted);
}

#[test]
fn exact_retry_does_not_verify_or_debit_again_and_changed_bytes_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let v = StorageOnlyVerifier::default();
    let calls = v.calls.clone();
    let mut ledger = open(&dir.path().join("ledger.sqlite"), &f, v);
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    let g = f.grant(7, &f.device);
    let a = f.authorize(7, &f.device);
    let request = genesis(&f);
    let first = ledger.apply(&g, &a, &request, || 120).unwrap();
    assert_eq!(ledger.apply(&g, &a, &request, || 200).unwrap(), first);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let mut changed = request.clone();
    changed.proof.push(4);
    sign(&mut changed, &f.device);
    assert_eq!(ledger.apply(&g, &a, &changed, || 201), Err(Error::Replay));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn real_authority_and_common_checkpoint_are_required_before_verifying() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let v = StorageOnlyVerifier::default();
    let calls = v.calls.clone();
    let mut ledger = open(&dir.path().join("ledger.sqlite"), &f, v);
    let g = f.grant(7, &f.device);
    let a = f.authorize(7, &f.device);
    let request = genesis(&f);
    assert_eq!(
        ledger.apply(&g, &a, &request, || 120),
        Err(Error::Admission)
    );
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    assert_eq!(
        ledger.admit_checkpoint(0, fr(9)),
        Err(Error::PolicyMismatch)
    );
    let mut forged = request.clone();
    forged.signature = B64.encode(&[0; 64]);
    assert_eq!(ledger.apply(&g, &a, &forged, || 120), Err(Error::Signature));
    let wrong_root = f.authorize(8, &f.device);
    assert_eq!(
        ledger.apply(&g, &wrong_root, &request, || 120),
        Err(Error::Admission)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    ledger.apply(&g, &a, &request, || 120).unwrap();
    let mut unsigned_scope = request.clone();
    unsigned_scope.statement.enrollment_root = fr(9);
    assert_eq!(
        ledger.apply(&g, &a, &unsigned_scope, || 120),
        Err(Error::Signature)
    );
}

#[test]
fn expiry_and_clock_changes_during_verification_have_no_effect() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let mut ledger = open(
        &dir.path().join("ledger.sqlite"),
        &f,
        StorageOnlyVerifier::default(),
    );
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    let g = f.grant(7, &f.device);
    let a = f.authorize(7, &f.device);
    let request = genesis(&f);
    for times in [[120, 120, 180], [120, 119, 120], [120, 120, 119]] {
        let index = Cell::new(0);
        let clock = || {
            let i = index.get();
            index.set(i + 1);
            times[i]
        };
        assert!(matches!(
            ledger.apply(&g, &a, &request, clock),
            Err(Error::Expired | Error::ClockRollback)
        ));
    }
    ledger.apply(&g, &a, &request, || 130).unwrap();
    assert_eq!(
        ledger.apply(&g, &a, &request, || 129),
        Err(Error::ClockRollback)
    );
}

#[test]
fn blocked_proof_allows_another_owner_to_commit_and_rechecks_shared_clock_floor() {
    for other_time in [120, 121] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        let f = Fixture::new();
        let (verifier, entered, release) = blocked_verifier();
        let mut slow = open(&path, &f, verifier);
        slow.admit_checkpoint(0, fr(8)).unwrap();
        let g = f.grant(7, &f.device);
        let a = f.authorize(7, &f.device);
        let first = genesis(&f);
        let other_grant = f.grant(8, &f.device);
        let other_authorization = f.authorize(8, &f.device);
        let mut other = genesis(&f);
        other.statement.owner = B64
            .decode(other_grant.member_id.as_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        other.request_id = [21; 32];
        sign(&mut other, &f.device);
        std::thread::scope(|scope| {
            let worker = scope.spawn(move || slow.apply(&g, &a, &first, || 120));
            entered.recv_timeout(Duration::from_secs(10)).unwrap();
            // Open/configuration and checkpoint publication must also remain
            // possible while the first verifier is deliberately blocked.
            let mut fast = open(&path, &f, StorageOnlyVerifier::default());
            fast.admit_checkpoint(0, fr(8)).unwrap();
            let accepted = fast.apply(&other_grant, &other_authorization, &other, || other_time);
            release.send(()).unwrap();
            let resumed = worker.join().unwrap();
            assert!(
                accepted.is_ok(),
                "another owner's commit must precede verifier release"
            );
            if other_time == 120 {
                assert!(resumed.is_ok());
            } else {
                assert_eq!(resumed, Err(Error::ClockRollback));
            }
        });
        let db = Connection::open(&path).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM cfrm_accounts", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            if other_time == 120 { 2 } else { 1 }
        );
    }
}

#[test]
fn successor_losing_during_verification_cannot_commit_its_marker_or_response() {
    for same_request_id in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        let f = Fixture::new();
        let mut fast = open(&path, &f, StorageOnlyVerifier::default());
        fast.admit_checkpoint(0, fr(8)).unwrap();
        let g = f.grant(7, &f.device);
        let a = f.authorize(7, &f.device);
        let first = genesis(&f);
        fast.apply(&g, &a, &first, || 120).unwrap();
        let losing = successor(&first, &f, 11);
        let mut winning = successor(&first, &f, if same_request_id { 11 } else { 12 });
        winning.statement.next_state = fr(3);
        winning.statement.settlement_marker = fr(16);
        sign(&mut winning, &f.device);
        let (verifier, entered, release) = blocked_verifier();
        let mut slow = open(&path, &f, verifier);
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| slow.apply(&g, &a, &losing, || 130));
            entered.recv_timeout(Duration::from_secs(10)).unwrap();
            let accepted = fast.apply(&g, &a, &winning, || 130);
            release.send(()).unwrap();
            let resumed = worker.join().unwrap();
            assert!(accepted.is_ok());
            assert_eq!(resumed, Err(Error::Replay));
        });
        let db = Connection::open(&path).unwrap();
        let (state, request): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT state,latest_request FROM cfrm_accounts",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, winning.statement.next_state);
        assert_eq!(request, winning.request_id);
        assert_eq!(
            db.query_row("SELECT marker FROM cfrm_accounts_markers", [], |row| row
                .get::<_, Vec<u8>>(0))
                .unwrap(),
            fr(16)
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM cfrm_accounts_requests", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            2
        );
    }
}

#[test]
fn concurrently_cached_request_bypasses_original_expiry_but_requires_live_authority() {
    for completed in [200, 900, 1000] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        let f = Fixture::new();
        let mut fast = open(&path, &f, StorageOnlyVerifier::default());
        fast.admit_checkpoint(0, fr(8)).unwrap();
        let g = f.grant(7, &f.device);
        let a = f.authorize(7, &f.device);
        let first = genesis(&f);
        fast.apply(&g, &a, &first, || 120).unwrap();
        let request = successor(&first, &f, 11);
        let (verifier, entered, release) = blocked_verifier();
        let mut slow = open(&path, &f, verifier);
        let now = AtomicU64::new(130);
        std::thread::scope(|scope| {
            let worker =
                scope.spawn(|| slow.apply(&g, &a, &request, || now.load(Ordering::SeqCst)));
            entered.recv_timeout(Duration::from_secs(10)).unwrap();
            let accepted = fast.apply(&g, &a, &request, || 130);
            now.store(completed, Ordering::SeqCst);
            release.send(()).unwrap();
            let resumed = worker.join().unwrap();
            let accepted = accepted.unwrap();
            if completed == 200 {
                assert_eq!(resumed.unwrap(), accepted);
            } else {
                assert_eq!(resumed, Err(Error::Expired));
            }
        });
        let db = Connection::open(&path).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM cfrm_accounts_requests", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM cfrm_accounts_markers", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            1
        );
    }
}

#[test]
fn checkpoint_slot_expiry_during_verification_cannot_commit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let f = Fixture::new();
    let mut configured = policy();
    configured.checkpoint_period_seconds = 150;
    let mut ledger = AccountLedger::open(
        &path,
        f.trust.clone(),
        configured,
        StorageOnlyVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap();
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    let times = [120, 120, 150];
    let index = Cell::new(0);
    let result = ledger.apply(
        &f.grant(7, &f.device),
        &f.authorize(7, &f.device),
        &genesis(&f),
        || {
            let i = index.get();
            index.set(i + 1);
            times[i]
        },
    );
    assert_eq!(result, Err(Error::Expired));
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM cfrm_accounts", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT clock_floor FROM cfrm_accounts_config", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        0
    );
}

#[test]
fn root_authorized_devices_share_one_compare_and_swap_frontier() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let f = Fixture::new();
    let mut ledger = open(&path, &f, StorageOnlyVerifier::default());
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    let g = f.grant(7, &f.device);
    let a = f.authorize(7, &f.device);
    let first = genesis(&f);
    ledger.apply(&g, &a, &first, || 120).unwrap();
    let second = successor(&first, &f, 11);
    ledger.apply(&g, &a, &second, || 121).unwrap();
    let device = SigningKey::from_bytes(&[55; 32]);
    let mut competing = successor(&first, &f, 12);
    competing.chat_public_key = B64.encode(&device.verifying_key().to_bytes());
    sign(&mut competing, &device);
    assert_eq!(
        ledger.apply(
            &f.grant(7, &device),
            &f.authorize(7, &device),
            &competing,
            || 122
        ),
        Err(Error::Replay)
    );
    let mut duplicate_event = successor(&second, &f, 13);
    sign(&mut duplicate_event, &f.device);
    assert_eq!(
        ledger.apply(&g, &a, &duplicate_event, || 123),
        Err(Error::Replay)
    );
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM cfrm_accounts_markers", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn failure_after_marker_insertion_rolls_back_marker_state_response_and_clock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let f = Fixture::new();
    let mut ledger = open(&path, &f, StorageOnlyVerifier::default());
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    let g = f.grant(7, &f.device);
    let a = f.authorize(7, &f.device);
    let first = genesis(&f);
    ledger.apply(&g, &a, &first, || 120).unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TRIGGER injected_failure BEFORE UPDATE ON cfrm_accounts
        BEGIN SELECT RAISE(ABORT,'storage-test failure'); END;",
    )
    .unwrap();
    let second = successor(&first, &f, 11);
    assert_eq!(ledger.apply(&g, &a, &second, || 130), Err(Error::Storage));
    assert_eq!(
        db.query_row("SELECT count(*) FROM cfrm_accounts_markers", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT version FROM cfrm_accounts", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM cfrm_accounts_requests", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT clock_floor FROM cfrm_accounts_config", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        120
    );
    db.execute_batch("DROP TRIGGER injected_failure").unwrap();
    ledger.apply(&g, &a, &second, || 130).unwrap();
}

#[test]
fn recovered_device_status_is_challenge_bound_and_returns_no_new_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let mut ledger = open(
        &dir.path().join("ledger.sqlite"),
        &f,
        StorageOnlyVerifier::default(),
    );
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    let first = genesis(&f);
    let accepted = ledger
        .apply(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &first,
            || 120,
        )
        .unwrap();
    let device = SigningKey::from_bytes(&[55; 32]);
    let mut request = AccountStatusRequest {
        community: first.statement.community,
        owner: first.statement.owner,
        request_id: None,
        challenge: [22; 32],
        chat_public_key: B64.encode(&device.verifying_key().to_bytes()),
        issued_at: 200,
        expires_at: 250,
        signature: String::new(),
    };
    request.signature = B64.encode(
        &device
            .sign(&account_status_bytes(&request).unwrap())
            .to_bytes(),
    );
    let response = ledger
        .status(
            &f.grant(7, &device),
            &f.authorize(7, &device),
            &request,
            || 210,
        )
        .unwrap();
    let operator = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    verify_account_status_response(&response, &request, &operator).unwrap();
    assert_eq!(response.acceptance, Some(accepted));
    request.challenge = [23; 32];
    request.signature = B64.encode(
        &device
            .sign(&account_status_bytes(&request).unwrap())
            .to_bytes(),
    );
    assert_eq!(
        verify_account_status_response(&response, &request, &operator),
        Err(Error::Replay)
    );
    let mut forged = response.clone();
    forged.acceptance = None;
    assert_eq!(
        verify_account_status_response(&forged, &request, &operator),
        Err(Error::Replay)
    );
}

#[test]
fn canonical_fields_versions_unknown_wire_fields_and_policy_scope_fail_closed() {
    let f = Fixture::new();
    let first = genesis(&f);
    let mut bad = first.clone();
    bad.statement.next_state = [255; 32];
    assert_eq!(account_request_bytes(&bad), Err(Error::InvalidInput));
    let mut bad = first.clone();
    bad.statement.next_version = 1;
    assert_eq!(account_request_bytes(&bad), Err(Error::InvalidInput));
    let mut bad = first.clone();
    bad.statement.policy.incoming_reservation = 2;
    assert_eq!(account_request_bytes(&bad), Err(Error::InvalidInput));
    let mut json = serde_json::to_value(first).unwrap();
    json["statement"]["peer"] = serde_json::json!([1, 2, 3]);
    assert!(serde_json::from_value::<AccountRequest>(json).is_err());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    drop(open(&path, &f, StorageOnlyVerifier::default()));
    let mut changed = policy();
    changed.account.initial_credit = 2;
    assert!(matches!(
        AccountLedger::open(
            &path,
            f.trust,
            changed,
            StorageOnlyVerifier::default(),
            SigningKey::from_bytes(&[9; 32])
        ),
        Err(Error::PolicyMismatch)
    ));
}

#[test]
#[ignore = "child process entry point; invoked only by independent_processes_race"]
fn ledger_process_worker() {
    let path = std::env::var("CFRM_ACCOUNT_TEST_DATABASE").unwrap();
    let id: u8 = std::env::var("CFRM_ACCOUNT_TEST_REQUEST")
        .unwrap()
        .parse()
        .unwrap();
    let gate = std::env::var("CFRM_ACCOUNT_TEST_GATE").unwrap();
    let f = Fixture::new();
    let mut ledger = open(Path::new(&path), &f, StorageOnlyVerifier::default());
    let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !Path::new(&gate).exists() {
        assert!(std::time::Instant::now() < until);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let request = successor(&genesis(&f), &f, id);
    let result = ledger.apply(
        &f.grant(7, &f.device),
        &f.authorize(7, &f.device),
        &request,
        || 130,
    );
    assert!(result.is_ok() || result == Err(Error::Replay));
}

#[test]
fn independent_processes_race_and_reopen_returns_the_committed_winner() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let gate = dir.path().join("go");
    let f = Fixture::new();
    let mut ledger = open(&path, &f, StorageOnlyVerifier::default());
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    ledger
        .apply(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &genesis(&f),
            || 120,
        )
        .unwrap();
    drop(ledger);
    let mut children = Vec::new();
    for id in [11, 12] {
        children.push(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "ledger_process_worker", "--ignored"])
                .env("CFRM_ACCOUNT_TEST_DATABASE", &path)
                .env("CFRM_ACCOUNT_TEST_REQUEST", id.to_string())
                .env("CFRM_ACCOUNT_TEST_GATE", &gate)
                .spawn()
                .unwrap(),
        );
    }
    std::fs::write(&gate, b"go").unwrap();
    for child in &mut children {
        assert!(child.wait().unwrap().success());
    }
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM cfrm_accounts_requests", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        db.query_row("SELECT version FROM cfrm_accounts", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    let winner: Vec<u8> = db
        .query_row(
            "SELECT latest_request FROM cfrm_accounts WHERE owner=?1",
            params![genesis(&f).statement.owner.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    let mut ledger = open(&path, &f, StorageOnlyVerifier::default());
    let request = successor(&genesis(&f), &f, winner[0]);
    assert_eq!(
        ledger
            .apply(
                &f.grant(7, &f.device),
                &f.authorize(7, &f.device),
                &request,
                || 200
            )
            .unwrap()
            .request_id
            .as_slice(),
        winner
    );
}

#[path = "accounting_ledger/tuning.rs"]
mod tuning;
