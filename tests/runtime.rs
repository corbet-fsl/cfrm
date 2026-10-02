#![cfg(all(feature = "server", not(target_arch = "wasm32")))]
mod support;
use cfrm::*;
use cgth::{cmmr, cswb, cthl};
use cmmr::{Clock, Store};
use ed25519_dalek::Signer as _;
use std::{num::NonZeroUsize, time::Duration};
use support::*;
use tower::ServiceExt;

#[derive(Clone)]
struct Time;
impl Clock for Time {
    fn now(&self) -> Result<u64, cmmr::Error> {
        Ok(2_000_000_000_000)
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
fn signed(mut request: Request, fixture: &Fixture) -> Request {
    let proof = request.possession().unwrap();
    let session = serde_json::from_slice(&proof.session).unwrap();
    let nonce = proof.request_nonce.as_slice().try_into().unwrap();
    let message = cswb::request_message(
        ORIGIN,
        request.info().name,
        &session,
        &nonce,
        &request.unsigned_bytes().unwrap(),
    );
    request.possession_mut().unwrap().signature = fixture.device.sign(&message).to_bytes().to_vec();
    request
}
fn possession(session: &[u8], nonce: u8) -> Possession {
    Possession {
        session: session.to_vec(),
        request_nonce: vec![nonce; 16],
        signature: vec![],
    }
}

#[tokio::test]
async fn real_http_admission_match_and_cancelled_mutation() {
    let now = Time.now().unwrap() / 1000;
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
        Time,
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
            clock: Time,
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
    let alice = Fixture::new("alice", 1, now).await;
    let bob = Fixture::new("bob", 1, now).await;
    assert_eq!(
        call(
            &app,
            Request::Challenge(ChallengeInput {
                publication: alice.publication.signed.clone()
            })
        )
        .await,
        Err(ErrorCode::AuthorityUnavailable)
    );
    assert_eq!(
        handle
            .execute(
                "https://foreign.example.test".into(),
                Call::new(Request::Challenge(ChallengeInput {
                    publication: alice.publication.signed.clone()
                }))
            )
            .await,
        Err(ErrorCode::Origin)
    );
    let fetch = handle.start_feed().await.unwrap();
    handle
        .complete_feed(
            fetch.id(),
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
    let entry = admission(&app, &alice).await;
    let Reply {
        response: Output::Enter(a),
        ..
    } = call(&app, entry.clone()).await.unwrap()
    else {
        panic!("enter output")
    };
    assert_eq!(call(&app, entry).await, Err(ErrorCode::ResetRequired));
    let entry = admission(&app, &bob).await;
    let Reply {
        response: Output::Enter(_),
        ..
    } = call(&app, entry).await.unwrap()
    else {
        panic!("enter output")
    };
    let query = signed(
        Request::Search(SearchInput {
            possession: possession(&a.session, 1),
            cursor: None,
            page_size: 3,
        }),
        &alice,
    );
    let Reply {
        response: Output::Search(page),
        ..
    } = call(&app, query.clone()).await.unwrap()
    else {
        panic!("search output")
    };
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].owner, b"bob");
    assert_eq!(page.entries[0].publication, bob.publication.signed);
    assert_eq!(call(&app, query).await, Err(ErrorCode::ResetRequired));
    let fetch = signed(
        Request::Ciphertext(CiphertextInput {
            possession: possession(&a.session, 2),
            owner: b"bob".to_vec(),
            revision: 1u64.to_be_bytes().to_vec(),
        }),
        &alice,
    );
    let Reply {
        response: Output::Ciphertext(ciphertext),
        ..
    } = call(&app, fetch).await.unwrap()
    else {
        panic!("ciphertext output")
    };
    assert_eq!(ciphertext.ciphertext, bob.publication.ciphertext);
    // Authenticated issuance only sees the original blinded request. The
    // anonymous request contains no session/member/device/room quota tag.
    use cgth::cmbl::{self, passes};
    let Reply {
        response: Output::RoomEpoch(common),
        ..
    } = call(
        &app,
        signed(
            Request::RoomEpoch(RoomEpochInput {
                possession: possession(&a.session, 20),
            }),
            &alice,
        ),
    )
    .await
    .unwrap()
    else {
        panic!("epoch output")
    };
    let epoch: passes::Epoch = serde_json::from_slice(&common.epoch).unwrap();
    let room = [41; 16];
    let prepared = passes::PreparedPass::new(&epoch, room, now * 1000).unwrap();
    let blinded = serde_json::to_vec(&prepared.request()).unwrap();
    let issue = |nonce, operation| {
        signed(
            Request::RoomIssue(RoomIssueInput {
                possession: possession(&a.session, nonce),
                operation: vec![operation; 16],
                blinded_request: blinded.clone(),
            }),
            &alice,
        )
    };
    let Reply {
        response: Output::RoomIssue(first),
        ..
    } = call(&app, issue(21, 1)).await.unwrap()
    else {
        panic!("issue output")
    };
    let Reply {
        response: Output::RoomIssue(retry),
        ..
    } = call(&app, issue(22, 1)).await.unwrap()
    else {
        panic!("retry output")
    };
    assert_eq!(first.signature, retry.signature);
    for operation in 2..=4 {
        call(&app, issue(22 + operation, operation)).await.unwrap();
    }
    assert_eq!(call(&app, issue(27, 5)).await, Err(ErrorCode::Capacity));
    let pass = prepared.finalize(&first.signature, now * 1000).unwrap();
    let command = cmbl::Request {
        room,
        operation: [51; 16],
        action: cmbl::Action::Resume {
            connection: pass.connection(),
        },
    };
    let input = RoomInput {
        room_pass: pass
            .prove(&command, &common.incarnation, now * 1000)
            .unwrap(),
        command: serde_json::to_vec(&command).unwrap(),
    };
    assert_eq!(
        call(&app, Request::RoomRelay(input.clone())).await,
        Err(ErrorCode::InvalidRequest)
    );
    let Reply {
        response: Output::RoomResume(result),
        ..
    } = call(&app, Request::RoomResume(input)).await.unwrap()
    else {
        panic!("resume output")
    };
    let resumed: cmbl::Outcome = serde_json::from_slice(&result.result).unwrap();
    assert_eq!(resumed.counter, 0);
    assert_eq!(resumed.active_connections, 1);
    let ordered = cmbl::Request {
        room,
        operation: [52; 16],
        action: cmbl::Action::Order {
            expected: 0,
            ciphertext: vec![9, 8, 7],
        },
    };
    let ordered_input = RoomInput {
        room_pass: pass
            .prove(&ordered, &common.incarnation, now * 1000)
            .unwrap(),
        command: serde_json::to_vec(&ordered).unwrap(),
    };
    let Reply {
        response: Output::RoomOrder(result),
        ..
    } = call(&app, Request::RoomOrder(ordered_input.clone()))
        .await
        .unwrap()
    else {
        panic!("order output")
    };
    let ordered_result: cmbl::Outcome = serde_json::from_slice(&result.result).unwrap();
    assert_eq!(ordered_result.counter, 1);
    assert_eq!(ordered_result.ordering, resumed.ordering);
    // Exact anonymous retry reconciles the actual original operation receipt.
    let Reply {
        response: Output::RoomOrder(retry),
        ..
    } = call(&app, Request::RoomOrder(ordered_input)).await.unwrap()
    else {
        panic!("order retry")
    };
    assert_eq!(result, retry);
    let read = cmbl::Request {
        room,
        operation: [53; 16],
        action: cmbl::Action::Read { after: 0 },
    };
    let read_input = RoomInput {
        room_pass: pass.prove(&read, &common.incarnation, now * 1000).unwrap(),
        command: serde_json::to_vec(&read).unwrap(),
    };
    let Reply {
        response: Output::RoomRead(result),
        ..
    } = call(&app, Request::RoomRead(read_input.clone()))
        .await
        .unwrap()
    else {
        panic!("read output")
    };
    let read_result: cmbl::Outcome = serde_json::from_slice(&result.result).unwrap();
    assert_eq!(read_result.frames[0].ciphertext, [9, 8, 7]);
    // Losing the issuer anchor fences old anonymous passes without replacing it.
    let anchor = storage.get("room-pass-issuer").await.unwrap().unwrap();
    storage.delete_generation(&anchor.generation).await.unwrap();
    assert_eq!(
        call(&app, Request::RoomRead(read_input)).await,
        Err(ErrorCode::AuthorityUnavailable)
    );
    assert_eq!(
        call(
            &app,
            signed(
                Request::RoomEpoch(RoomEpochInput {
                    possession: possession(&a.session, 28)
                }),
                &alice
            )
        )
        .await,
        Err(ErrorCode::AuthorityUnavailable)
    );
    // Cancellation after queue admission cannot abandon a mutation midway.
    let heartbeat = signed(
        Request::Heartbeat(HeartbeatInput {
            possession: possession(&a.session, 3),
            expected_revision: a.revision.clone(),
        }),
        &alice,
    );
    {
        let future = handle.execute(ORIGIN.into(), Call::new(heartbeat));
        let mut future = std::pin::pin!(future);
        assert!(futures_util::poll!(&mut future).is_pending());
    }
    handle.next_feed().await.unwrap(); // FIFO barrier after the cancelled waiter.
    let committed = storage.get("swb_alice").await.unwrap().unwrap();
    assert_ne!(committed.revision.0.to_vec(), a.revision);
    drop(app);
    drop(handle);
    worker.await.unwrap();
    assert_eq!(storage.state(), cmmr::State::Closed);
}
