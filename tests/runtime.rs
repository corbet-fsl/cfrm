#![cfg(all(feature = "server", not(target_arch = "wasm32")))]
mod support;
use cfrm::*;
use cgth::{cmmr, cswb, cthl};
use cmmr::{Clock, Store};
use ed25519_dalek::Signer as _;
use std::{
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use support::*;
use tower::ServiceExt;

#[derive(Clone)]
struct Time {
    milliseconds: Arc<AtomicU64>,
    reads: Arc<AtomicU64>,
    regression_at: Arc<AtomicU64>,
    completion_at: Arc<AtomicU64>,
    completion_ms: Arc<AtomicU64>,
}
impl Time {
    fn new() -> Self {
        Self {
            milliseconds: Arc::new(AtomicU64::new(2_000_000_000_000)),
            reads: Arc::new(AtomicU64::new(0)),
            regression_at: Arc::new(AtomicU64::new(u64::MAX)),
            completion_at: Arc::new(AtomicU64::new(u64::MAX)),
            completion_ms: Arc::new(AtomicU64::new(0)),
        }
    }
    fn advance(&self, milliseconds: u64) {
        self.milliseconds.fetch_add(milliseconds, Ordering::SeqCst);
    }
}
impl Clock for Time {
    fn now(&self) -> Result<u64, cmmr::Error> {
        let read = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
        let now = self.milliseconds.load(Ordering::SeqCst);
        Ok(if read == self.regression_at.load(Ordering::SeqCst) {
            now - 1
        } else if read == self.completion_at.load(Ordering::SeqCst) {
            self.completion_ms.load(Ordering::SeqCst)
        } else {
            now
        })
    }
}
#[derive(Clone)]
struct Random;
impl cswb::Tokens for Random {
    fn next(&self) -> Result<[u8; 16], cswb::Error> {
        use ckmg::Entropy;
        let mut bytes = [0; 16];
        ckmg::SystemEntropy
            .fill(&mut bytes)
            .map_err(|_| cswb::Error::Invalid)?;
        Ok(bytes)
    }
}
async fn call(app: &axum::Router, request: Request) -> Result<Reply, ErrorCode> {
    let path = format!("/v1/{}", request.info().name);
    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(path)
                .header("Host", "forum.example.test")
                .header("Origin", ORIGIN)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&Call::new(request)).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["access-control-allow-origin"], ORIGIN);
    let bytes = axum::body::to_bytes(response.into_body(), 1_048_576)
        .await
        .unwrap();
    if let Ok(failure) = serde_json::from_slice::<Failure>(&bytes) {
        Err(failure.error)
    } else {
        Ok(serde_json::from_slice(&bytes).unwrap())
    }
}
async fn admission(app: &axum::Router, fixture: &Fixture) -> Request {
    let Reply {
        response: Output::Challenge(challenge),
        ..
    } = call(
        app,
        Request::Challenge(ChallengeInput {
            publication: fixture.publication.signed.clone(),
        }),
    )
    .await
    .unwrap()
    else {
        panic!("challenge output")
    };
    let decoded = serde_json::from_slice(&challenge.challenge).unwrap();
    let signature = fixture
        .device
        .sign(&cswb::challenge_message(
            ORIGIN,
            "garden",
            &decoded,
            &fixture.publication.signed,
        ))
        .to_bytes()
        .to_vec();
    Request::Enter(EnterInput {
        challenge: challenge.challenge,
        signature,
        publication: fixture.publication.signed.clone(),
        record_proof: vec![],
    })
}
fn possession(session: &[u8], nonce: u8) -> Possession {
    Possession {
        session: session.to_vec(),
        request_nonce: vec![nonce; 16],
        signature: vec![],
    }
}

fn runtime(
    clock: &Time,
) -> (
    axum::Router,
    runtime::Handle,
    tokio::task::JoinHandle<()>,
    cvtl::Volatile<Time>,
) {
    runtime_with_request_clock(clock, clock)
}

fn runtime_with_request_clock(
    clock: &Time,
    request_clock: &Time,
) -> (
    axum::Router,
    runtime::Handle,
    tokio::task::JoinHandle<()>,
    cvtl::Volatile<Time>,
) {
    let now = clock.now().unwrap() / 1000;
    let issuer = issuer(now);
    let assurance = csrn::Assurance::new(
        cchr::Configuration {
            origin: "https://identity.example.test".into(),
            community: "garden".into(),
            key_ring: issuer.key_ring().to_cbor(),
            minimum_revision: 1,
            ring_revision: 0,
        },
        csrn::feed::Config {
            retry_entropy: 15,
            refresh_seconds: 30,
            poll_seconds: 1,
            request_seconds: 30,
            initial_backoff_seconds: 1,
            maximum_backoff_seconds: 10,
            maximum_staleness_seconds: 60,
        },
    )
    .unwrap();
    let storage: cvtl::Volatile<_> = cvtl::Volatile::memory(
        cmmr::Scope::new("garden", "boot").unwrap(),
        cmmr::Limits {
            records: 128,
            value_bytes: 262144,
            batch: 4,
            indexes_per_record: 4,
            page: 8,
            ttl_ms: 600000,
        },
        clock.clone(),
    )
    .unwrap();
    let throttle = cthl::Throttle::new(
        "garden",
        actions().into_iter().map(|action| {
            (
                action.name,
                cthl::Limit::new(100, Duration::from_secs(1)).unwrap(),
            )
        }),
        cthl::MemoryStore::new(NonZeroUsize::new(32).unwrap()),
    )
    .unwrap();
    let service = runtime::Service::new(
        assurance,
        runtime::Parts {
            storage: storage.clone(),
            clock: request_clock.clone(),
            tokens: Random,
            throttle,
        },
        runtime::Configuration {
            community: "garden".into(),
            incarnation: "boot".into(),
            admission_action: ACTION.into(),
            origins: vec![ORIGIN.into()],
            maximum_snapshot_age: 300,
            request_bytes: 1_048_576,
            presence: cswb::Limits {
                lease_ms: 10000,
                publication_bytes: cpfl::MAX_PROFILE_BYTES,
                ciphertext_bytes: cpfl::MAX_PROFILE_BYTES,
            },
            lookup: cgth::clkp::LookupLimits {
                candidates: 3,
                publication_bytes: cpfl::MAX_PROFILE_BYTES * 3,
            },
            room_epoch: runtime::RoomEpochConfiguration {
                epoch: 1,
                valid_from_ms: now * 1000,
                valid_until_ms: (now + 60) * 1000,
            },
            rooms: cgth::cmbl::Limits {
                connections: 4,
                relay_messages: 4,
                message_bytes: 1024,
                lifetime_ms: 10000,
                proof_bytes: cgth::cmbl::passes::MAX_PROOF_BYTES,
                operation_receipts: 16,
            },
        },
        clean,
    )
    .unwrap();
    let (handle, worker) = service.spawn(16, Duration::from_millis(10)).unwrap();
    let app = http::router_with(
        http::Limits {
            hosts: vec!["forum.example.test".into()],
            origins: vec![ORIGIN.into()],
            body_bytes: 1_048_576,
            concurrent: 4,
            body_timeout: Duration::from_secs(5),
        },
        handle.clone(),
    )
    .unwrap();
    (app, handle, worker, storage)
}

async fn bootstrap(handle: &runtime::Handle, now: u64) {
    let request = handle.start_feed().await.unwrap();
    handle
        .complete_feed(
            request.id(),
            serde_json::to_vec(&feed(
                now,
                1,
                serde_json::json!({"members":[],"devices":[]}),
            ))
            .unwrap(),
            false,
        )
        .await
        .unwrap();
}

async fn announce_revision(handle: &runtime::Handle, clock: &Time) {
    clock.advance(1000);
    let request = handle.next_feed().await.unwrap().unwrap();
    assert!(matches!(
        request.action(),
        csrn::feed::Action::Poll { revision: 1 }
    ));
    handle
        .complete_feed(
            request.id(),
            serde_json::to_vec(&serde_json::json!({
                "revision":2,"policy_epoch":2,"changed":true,
            }))
            .unwrap(),
            true,
        )
        .await
        .unwrap();
}

async fn install_revision(handle: &runtime::Handle, now: u64, revoked: serde_json::Value) {
    let request = handle.next_feed().await.unwrap().unwrap();
    assert!(matches!(request.action(), csrn::feed::Action::Fetch));
    handle
        .complete_feed(
            request.id(),
            serde_json::to_vec(&feed(now, 2, revoked)).unwrap(),
            false,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn a_clock_regression_at_request_completion_refuses_the_credential_challenge() {
    let clock = Time::new();
    let request_clock = Time::new();
    clock.advance(1);
    request_clock.advance(1);
    let now = clock.now().unwrap() / 1000;
    let alice = Fixture::new("alice", 1, now).await;
    let (app, handle, worker, _) = runtime_with_request_clock(&clock, &request_clock);
    bootstrap(&handle, now).await;
    let request = Request::Challenge(ChallengeInput {
        publication: alice.publication.signed.clone(),
    });

    // Equal request timestamps are valid. Measure the real owner path so the
    // next request rolls back only at the final service completion sample.
    let before = request_clock.reads.load(Ordering::SeqCst);
    let result = call(&app, request.clone()).await.unwrap();
    let reads = request_clock.reads.load(Ordering::SeqCst) - before;
    let Output::Challenge(challenge) = result.response else {
        panic!("challenge output")
    };
    assert!(!challenge.challenge.is_empty());
    assert!(reads >= 2);

    // The one-millisecond rollback stays within the same whole-second value
    // used by Charter, and happens after the real owner has completed.
    let completion = request_clock.reads.load(Ordering::SeqCst) + reads;
    request_clock
        .regression_at
        .store(completion, Ordering::SeqCst);
    let result = call(&app, request).await;
    assert_eq!(request_clock.reads.load(Ordering::SeqCst), completion);
    assert_eq!(result, Err(ErrorCode::AuthorityUnavailable));

    drop(app);
    drop(handle);
    worker.await.unwrap();
}

#[tokio::test]
async fn challenge_completion_obeys_its_exclusive_owner_deadline() {
    let clock = Time::new();
    let request_clock = Time::new();
    let now = clock.now().unwrap() / 1000;
    let alice = Fixture::new("alice", 1, now).await;
    let (app, handle, worker, _) = runtime_with_request_clock(&clock, &request_clock);
    bootstrap(&handle, now).await;
    let Output::Settings(settings) = call(&app, Request::Settings(SettingsInput {}))
        .await
        .unwrap()
        .response
    else {
        panic!("settings output")
    };
    let request = Request::Challenge(ChallengeInput {
        publication: alice.publication.signed.clone(),
    });

    // Measure the real signed-profile/owner path with a separate stable storage
    // clock, then advance only the service's final completion sample.
    let before = request_clock.reads.load(Ordering::SeqCst);
    let result = call(&app, request.clone()).await.unwrap();
    let reads = request_clock.reads.load(Ordering::SeqCst) - before;
    let Output::Challenge(output) = result.response else {
        panic!("challenge output")
    };
    let challenge: cswb::Challenge = serde_json::from_slice(&output.challenge).unwrap();
    assert_eq!(challenge.expires_at_ms, clock.now().unwrap() + 10000);
    assert!(reads >= 2);
    // The original trust feed stays valid beyond all three completion times.
    assert!(challenge.expires_at_ms + 1 < settings.valid_until * 1000);

    for completed_at in [
        challenge.expires_at_ms - 1,
        challenge.expires_at_ms,
        challenge.expires_at_ms + 1,
    ] {
        let completion = request_clock.reads.load(Ordering::SeqCst) + reads;
        request_clock
            .completion_ms
            .store(completed_at, Ordering::SeqCst);
        request_clock
            .completion_at
            .store(completion, Ordering::SeqCst);
        let result = call(&app, request.clone()).await;
        // Reaching this sample proves the refusal did not come from an earlier
        // owner check, storage operation or stale-trust path.
        assert_eq!(request_clock.reads.load(Ordering::SeqCst), completion);
        if completed_at < challenge.expires_at_ms {
            let Output::Challenge(output) = result.unwrap().response else {
                panic!("challenge output")
            };
            let issued: cswb::Challenge = serde_json::from_slice(&output.challenge).unwrap();
            assert_eq!(issued.expires_at_ms, challenge.expires_at_ms);
        } else {
            assert_eq!(result, Err(ErrorCode::AuthorityUnavailable));
        }
    }

    drop(app);
    drop(handle);
    worker.await.unwrap();
}

#[tokio::test]
async fn missing_accounting_currentness_refuses_every_member_action_without_attendance() {
    let clock = Time::new();
    let now = clock.now().unwrap() / 1000;
    let (app, handle, worker, storage) = runtime(&clock);
    bootstrap(&handle, now).await;
    assert!(matches!(
        call(&app, Request::Settings(SettingsInput {}))
            .await
            .unwrap()
            .response,
        Output::Settings(_)
    ));
    let alice = Fixture::new("alice", 1, now).await;
    // This is an original credential, signed public profile and device proof.
    // They cannot replace the absent accounting owner's currentness evidence.
    let entry = admission(&app, &alice).await;
    let proof = possession(&[], 1);
    let room = RoomInput {
        room_pass: vec![],
        command: vec![],
    };
    let requests = vec![
        entry.clone(),
        Request::Replace(ReplaceInput {
            possession: proof.clone(),
            expected_revision: vec![],
            publication: alice.publication.signed.clone(),
            record_proof: vec![],
        }),
        Request::Heartbeat(HeartbeatInput {
            possession: proof.clone(),
            expected_revision: vec![],
        }),
        Request::Depart(DepartInput {
            possession: proof.clone(),
        }),
        Request::Search(SearchInput {
            possession: proof.clone(),
            cursor: None,
            page_size: 3,
        }),
        Request::Watch(WatchInput {
            possession: proof.clone(),
            cursor: vec![],
        }),
        Request::Ciphertext(CiphertextInput {
            possession: proof.clone(),
            owner: b"alice".to_vec(),
            revision: vec![],
        }),
        Request::RoomEpoch(RoomEpochInput {
            possession: proof.clone(),
        }),
        Request::RoomIssue(RoomIssueInput {
            possession: proof,
            operation: vec![],
            blinded_request: vec![],
        }),
        Request::RoomConnect(room.clone()),
        Request::RoomRenew(room.clone()),
        Request::RoomDisconnect(room.clone()),
        Request::RoomRead(room.clone()),
        Request::RoomOrder(room.clone()),
        Request::RoomRelay(room.clone()),
        Request::RoomResume(room.clone()),
        Request::RoomHandover(room),
    ];
    assert_eq!(
        requests
            .iter()
            .map(|request| request.info().name)
            .collect::<Vec<_>>(),
        actions()
            .into_iter()
            .filter(|action| !matches!(
                action.requirement,
                Requirement::PublishedPolicy | Requirement::Credential
            ))
            .map(|action| action.name)
            .collect::<Vec<_>>()
    );
    for request in requests {
        assert_eq!(
            call(&app, request.clone()).await,
            Err(ErrorCode::AuthorityUnavailable)
        );
        assert_eq!(
            handle.execute(ORIGIN.into(), Call::new(request)).await,
            Err(ErrorCode::AuthorityUnavailable)
        );
        assert!(storage.get("swb_alice").await.unwrap().is_none());
        assert!(storage.get("room-pass-issuer").await.unwrap().is_none());
    }
    let Request::Enter(mut supplied_proof) = entry.clone() else {
        panic!("entry")
    };
    supplied_proof.record_proof = vec![1, 2, 3];
    assert_eq!(
        call(&app, Request::Enter(supplied_proof)).await,
        Err(ErrorCode::AuthorityUnavailable)
    );
    // Dropping the result receiver cannot let an already queued request bypass
    // the same refusal. The following command is the controller's FIFO barrier.
    {
        let future = handle.execute(ORIGIN.into(), Call::new(entry));
        let mut future = std::pin::pin!(future);
        assert!(futures_util::poll!(&mut future).is_pending());
    }
    handle.next_feed().await.unwrap();
    assert!(storage.get("swb_alice").await.unwrap().is_none());
    assert!(storage.get("room-pass-issuer").await.unwrap().is_none());
    drop(app);
    drop(handle);
    worker.await.unwrap();
    assert_eq!(storage.state(), cmmr::State::Closed);
}

#[tokio::test]
async fn credential_challenges_require_ready_trust_exact_origin_and_a_current_member() {
    let clock = Time::new();
    let now = clock.now().unwrap() / 1000;
    let (app, handle, worker, storage) = runtime(&clock);
    let alice = Fixture::new("alice", 1, now).await;
    let request = Request::Challenge(ChallengeInput {
        publication: alice.publication.signed.clone(),
    });
    assert_eq!(
        call(&app, request.clone()).await,
        Err(ErrorCode::AuthorityUnavailable)
    );
    assert_eq!(
        handle
            .execute(
                "https://foreign.example.test".into(),
                Call::new(request.clone())
            )
            .await,
        Err(ErrorCode::Origin)
    );
    bootstrap(&handle, now).await;
    assert!(matches!(
        call(&app, request.clone()).await.unwrap().response,
        Output::Challenge(_)
    ));
    announce_revision(&handle, &clock).await;
    assert_eq!(
        call(&app, request.clone()).await,
        Err(ErrorCode::AuthorityUnavailable)
    );
    install_revision(
        &handle,
        now,
        serde_json::json!({"members":["alice"],"devices":[]}),
    )
    .await;
    assert_eq!(
        call(&app, request).await,
        Err(ErrorCode::AuthorityUnavailable)
    );
    assert!(storage.get("swb_alice").await.unwrap().is_none());
    drop(app);
    drop(handle);
    worker.await.unwrap();
    assert_eq!(storage.state(), cmmr::State::Closed);
}
