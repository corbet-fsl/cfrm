//! Real SQLite/authority tests with the parent module's synthetic proof verifier.
//! These do not prove the circuit's immutable slot-deadline relation.

use super::*;

fn stored(path: &Path) -> Vec<Vec<String>> {
    let db = Connection::open(path).unwrap();
    [
        "SELECT hex(config)||':'||clock_floor FROM cfrm_accounts_config ORDER BY singleton",
        "SELECT hex(owner)||':'||hex(root_key)||':'||version||':'||hex(state)||':'||hex(latest_request) FROM cfrm_accounts ORDER BY owner",
        "SELECT hex(owner)||':'||hex(request_id)||':'||hex(acceptance) FROM cfrm_accounts_requests ORDER BY owner,request_id",
        "SELECT hex(owner)||':'||hex(marker) FROM cfrm_accounts_markers ORDER BY owner,marker",
        "SELECT slot||':'||hex(root) FROM cfrm_accounts_checkpoints ORDER BY slot",
    ]
    .into_iter()
    .map(|sql| {
        db.prepare(sql).unwrap().query_map([], |row| row.get(0)).unwrap()
            .collect::<rusqlite::Result<Vec<String>>>().unwrap()
    })
    .collect()
}

fn with_policy(
    mut request: AccountRequest,
    account: &AccountPolicy,
    f: &Fixture,
) -> AccountRequest {
    request.statement.policy = account.clone();
    request.statement.policy_digest = account.digest(&request.statement.community).unwrap();
    request.statement.valid_until = account.proof_valid_until(request.statement.now).unwrap();
    sign(&mut request, &f.device);
    request
}

#[test]
fn invalid_tuning_revision_clock_and_storage_failure_are_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
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
    let before = stored(&path);
    let tuning = ledger.waiting_period().unwrap();
    for seconds in [0, 999, 9_007_199_254_740_992] {
        assert_eq!(
            ledger.update_waiting_period(0, seconds, || 130),
            Err(Error::InvalidInput)
        );
        assert_eq!(ledger.waiting_period().unwrap(), tuning);
        assert_eq!(stored(&path), before);
    }
    // A valid integer still cannot promise a refund at/after policy expiry.
    for seconds in [1870, 1900] {
        assert_eq!(
            ledger.update_waiting_period(0, seconds, || 130),
            Err(Error::Expired)
        );
        assert_eq!(ledger.waiting_period().unwrap(), tuning);
        assert_eq!(stored(&path), before);
    }
    assert_eq!(
        ledger.update_waiting_period(1, 1500, || 130),
        Err(Error::PolicyMismatch)
    );
    assert_eq!(
        ledger.update_waiting_period(0, 1500, || 119),
        Err(Error::ClockRollback)
    );
    let call = Cell::new(0);
    assert_eq!(
        ledger.update_waiting_period(0, 1500, || {
            let n = call.get();
            call.set(n + 1);
            if n == 0 {
                130
            } else {
                129
            }
        }),
        Err(Error::ClockRollback)
    );
    assert_eq!(
        ledger.update_waiting_period(0, 1500, || 2000),
        Err(Error::Expired)
    );
    assert_eq!(ledger.waiting_period().unwrap(), tuning);
    assert_eq!(stored(&path), before);

    let db = Connection::open(&path).unwrap();
    // Reject the clock write after config has changed inside the transaction.
    db.execute_batch("CREATE TRIGGER reject_tuning_clock BEFORE UPDATE OF clock_floor ON cfrm_accounts_config BEGIN SELECT RAISE(ABORT,'synthetic storage failure'); END;").unwrap();
    assert_eq!(
        ledger.update_waiting_period(0, 1500, || 130),
        Err(Error::Storage)
    );
    assert_eq!(ledger.waiting_period().unwrap(), tuning);
    assert_eq!(stored(&path), before);
    db.execute_batch("DROP TRIGGER reject_tuning_clock;")
        .unwrap();
    let changed = ledger.update_waiting_period(0, 1500, || 130).unwrap();
    assert_eq!((changed.revision, changed.seconds), (1, 1500));
    assert_ne!(changed.policy_digest, tuning.policy_digest);
    assert_eq!(changed.state_policy_digest, tuning.state_policy_digest);
}

#[test]
fn restart_loads_durable_wait_and_preserves_genesis_and_exact_old_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let f = Fixture::new();
    let g = f.grant(7, &f.device);
    let a = f.authorize(7, &f.device);
    let first = genesis(&f);
    let mut ledger = open(&path, &f, StorageOnlyVerifier::default());
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    let accepted = ledger.apply(&g, &a, &first, || 120).unwrap();
    let tuning = ledger.update_waiting_period(0, 1500, || 130).unwrap();
    drop(ledger);
    let verifier = StorageOnlyVerifier::default();
    let calls = verifier.calls.clone();
    // open() supplies the old bootstrap wait; persisted configuration wins.
    let mut reopened = open(&path, &f, verifier);
    assert_eq!(reopened.waiting_period().unwrap(), tuning);
    assert_eq!(reopened.account_policy().abandon_after, 1500);
    assert_eq!(reopened.apply(&g, &a, &first, || 200).unwrap(), accepted);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let mut second_genesis = first.clone();
    second_genesis.request_id = [12; 32];
    second_genesis.statement.now = 201;
    second_genesis.issued_at = 201;
    second_genesis.expires_at = 251;
    let second_genesis = with_policy(second_genesis, reopened.account_policy(), &f);
    let before = stored(&path);
    assert_eq!(
        reopened.apply(&g, &a, &second_genesis, || 201),
        Err(Error::Replay)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(stored(&path), before);
}

#[test]
fn state_binding_and_restart_pin_every_policy_field_except_wait() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let f = Fixture::new();
    let mut ledger = open(&path, &f, StorageOnlyVerifier::default());
    let original = ledger.waiting_period().unwrap();
    let tuned = ledger.update_waiting_period(0, 1500, || 120).unwrap();
    assert_eq!(original.state_policy_digest, tuned.state_policy_digest);
    let community = genesis(&f).statement.community;
    let account = ledger.account_policy().clone();
    let encoded = serde_json::to_value(&account).unwrap();
    let before = stored(&path);
    // This includes future additions to the public policy unless explicitly
    // designated as mutable. These fixture values allow each increment.
    for field in encoded
        .as_object()
        .unwrap()
        .keys()
        .filter(|name| name.as_str() != "abandonAfter")
    {
        let mut changed = encoded.clone();
        let key = field.as_str();
        changed[key] = serde_json::Value::from(changed[key].as_u64().unwrap() + 1);
        let changed: AccountPolicy = serde_json::from_value(changed).unwrap();
        assert_ne!(
            changed.state_digest(&community).unwrap(),
            tuned.state_policy_digest,
            "{field}"
        );
        let supplied = AccountLedgerPolicy {
            account: changed,
            ..policy()
        };
        let reopened = AccountLedger::open(
            &path,
            f.trust.clone(),
            supplied,
            StorageOnlyVerifier::default(),
            SigningKey::from_bytes(&[9; 32]),
        );
        assert!(matches!(reopened, Err(Error::PolicyMismatch)), "{field}");
        assert_eq!(stored(&path), before);
    }
}

#[test]
fn stale_handles_and_old_proofs_reject_before_verify_then_reload_accepts_successor() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let f = Fixture::new();
    let g = f.grant(7, &f.device);
    let a = f.authorize(7, &f.device);
    let first = genesis(&f);
    let mut writer = open(&path, &f, StorageOnlyVerifier::default());
    writer.admit_checkpoint(0, fr(8)).unwrap();
    let accepted = writer.apply(&g, &a, &first, || 120).unwrap();
    let verifier = StorageOnlyVerifier::default();
    let calls = verifier.calls.clone();
    let mut stale = open(&path, &f, verifier);
    let tuning = writer.update_waiting_period(0, 1500, || 130).unwrap();
    let old_proof = successor(&first, &f, 11);
    let before = stored(&path);
    assert_eq!(
        stale.apply(&g, &a, &old_proof, || 130),
        Err(Error::PolicyMismatch)
    );
    assert_eq!(
        stale.update_waiting_period(0, 1700, || 130),
        Err(Error::PolicyMismatch)
    );
    assert_eq!(stored(&path), before);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(stale.waiting_period().unwrap().revision, 0);
    assert_eq!(stale.reload_policy().unwrap(), tuning);
    assert_eq!(
        stale.apply(&g, &a, &old_proof, || 130),
        Err(Error::PolicyMismatch)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let successor = with_policy(old_proof, stale.account_policy(), &f);
    let next = stale.apply(&g, &a, &successor, || 130).unwrap();
    assert_eq!(next.statement.previous_state, first.statement.next_state);
    assert_eq!(next.statement.next_version, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // Policy changes never destroy a previously accepted exact response.
    assert_eq!(stale.apply(&g, &a, &first, || 200).unwrap(), accepted);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn tuning_during_blocked_verification_rejects_the_stale_transition_atomically() {
    // A revision change also invalidates handles if the configured value stays
    // the same; a matching policy digest does not replace configuration CAS.
    for seconds in [1000, 1500] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        let f = Fixture::new();
        let g = f.grant(7, &f.device);
        let a = f.authorize(7, &f.device);
        let first = genesis(&f);
        let mut writer = open(&path, &f, StorageOnlyVerifier::default());
        writer.admit_checkpoint(0, fr(8)).unwrap();
        writer.apply(&g, &a, &first, || 120).unwrap();
        let request = successor(&first, &f, 11);
        let (verifier, entered, release) = blocked_verifier();
        let mut slow = open(&path, &f, verifier);
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| slow.apply(&g, &a, &request, || 130));
            entered.recv_timeout(Duration::from_secs(10)).unwrap();
            let changed = writer.update_waiting_period(0, seconds, || 130);
            let after_tuning = stored(&path);
            release.send(()).unwrap();
            let resumed = worker.join().unwrap();
            assert_eq!(changed.unwrap().revision, 1);
            assert_eq!(resumed, Err(Error::PolicyMismatch));
            assert_eq!(stored(&path), after_tuning);
        });
        assert_eq!(slow.waiting_period().unwrap().revision, 0);
        assert_eq!(
            slow.reload_policy().unwrap(),
            writer.waiting_period().unwrap()
        );
    }
}

#[test]
fn competing_tuning_connections_commit_exactly_one_expected_revision() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let f = Fixture::new();
    let mut first = open(&path, &f, StorageOnlyVerifier::default());
    let mut second = open(&path, &f, StorageOnlyVerifier::default());
    let results = std::thread::scope(|scope| {
        let left = scope.spawn(|| first.update_waiting_period(0, 1500, || 120));
        let right = scope.spawn(|| second.update_waiting_period(0, 1700, || 120));
        [left.join().unwrap(), right.join().unwrap()]
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(Error::PolicyMismatch)))
            .count(),
        1
    );
    let winner = results.into_iter().find_map(Result::ok).unwrap();
    assert_eq!(winner.revision, 1);
    assert_eq!(
        open(&path, &f, StorageOnlyVerifier::default())
            .waiting_period()
            .unwrap(),
        winner
    );
    assert_eq!(first.reload_policy().unwrap(), winner);
    assert_eq!(second.reload_policy().unwrap(), winner);
}
