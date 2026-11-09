//! Actual four-artifact native proof, signed owners and TCP HTTP on two workers.
//! Linux process ownership is tested without an accepting verifier substitute.
#![cfg(all(feature = "server", target_os = "linux"))]

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

#[path = "native_record/fixture.rs"]
mod fixture;
#[path = "native_record/g1.rs"]
mod g1;
#[path = "native_record/host.rs"]
mod host;
#[path = "native_record/rooms.rs"]
mod rooms;
use fixture::Fixture;
use g1::G1;
use host::{Delay, Host, call, exchange};

fn member() -> String {
    data_encoding::HEXLOWER.encode(&[7; 48])
}
async fn entry(host: &Host, native: &Fixture, g1: &G1) -> Request {
    let Output::Challenge(value) = call(
        host.address,
        Request::Challenge(ChallengeInput {
            publication: g1.publication.signed.clone(),
        }),
    )
    .await
    .unwrap()
    .response
    else {
        panic!("Actual challenge output required")
    };
    let challenge: cswb::Challenge = serde_json::from_slice(&value.challenge).unwrap();
    let context = serde_json::from_slice(&challenge.payload).unwrap();
    let presentation = native.presentation(context);
    let signature = g1
        .device
        .sign(&cswb::challenge_message(
            g1::ORIGIN,
            &native.material.community,
            &challenge,
            &g1.publication.signed,
        ))
        .to_bytes()
        .to_vec();
    Request::Enter(EnterInput {
        challenge: value.challenge,
        signature,
        publication: g1.publication.signed.clone(),
        record_proof: serde_json::to_vec(&presentation).unwrap(),
    })
}
fn search(g1: &G1, session: &[u8], nonce: u8) -> Request {
    let mut request = Request::Search(SearchInput {
        possession: Possession {
            session: session.to_vec(),
            request_nonce: vec![nonce; 16],
            signature: vec![],
        },
        cursor: None,
        page_size: 3,
    });
    let decoded: cswb::Session = serde_json::from_slice(session).unwrap();
    let signature = g1
        .device
        .sign(&cswb::request_message(
            g1::ORIGIN,
            request.info().name,
            &decoded,
            &[nonce; 16],
            &request.unsigned_bytes().unwrap(),
        ))
        .to_bytes()
        .to_vec();
    request.possession_mut().unwrap().signature = signature;
    request
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_http_native_entry_keeps_timer_and_feed_transport_live_then_installs_queued_feed() {
    if std::env::var_os("CBLC_RECORD_EPOCH_FIXTURE").is_none() {
        eprintln!(
            "skipped: CBLC_RECORD_EPOCH_FIXTURE is required (genuine retained CBLC four-artifact fixture)"
        );
        return;
    }
    let native = Fixture::load();
    let g1 = G1::new(&native, &member(), 1, 10_000).await;
    let delay = Delay::new();
    let host = Host::new(&native, delay.executable.clone()).await;
    // The zero-delay wrapper must execute the original native worker and real
    // proof successfully before its scheduling-delay behavior is exercised.
    let enter = entry(&host, &native, &g1).await;
    let Output::Enter(accepted) = call(host.address, enter).await.unwrap().response else {
        panic!("Genuine native entry must succeed")
    };
    assert!(
        host.storage
            .get(&cswb::attendance_key(
                &member(),
                &g1.device.verifying_key().to_bytes()
            ))
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(accepted.revision.len(), 16);
    host.clock.0.fetch_add(1000, Ordering::SeqCst);
    let refresh = host.handle.next_feed().await.unwrap().unwrap();
    assert!(matches!(refresh.action(), csrn::feed::Action::Fetch));

    let feed = serde_json::to_vec(&g1::feed(&native, 10_000, 2)).unwrap();
    let body = feed.clone();
    let app = axum::Router::new().route(
        "/feed",
        axum::routing::get(move || {
            let body = body.clone();
            async move { body }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let feed_address = listener.local_addr().unwrap();
    let network = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    delay.seconds(3);
    let request = search(&g1, &accepted.session, 1);
    let address = host.address;
    let reading = tokio::spawn(async move { call(address, request).await });
    let pid = delay.started().await;
    assert!(std::path::Path::new(&format!("/proc/{pid}")).exists());
    tokio::time::timeout(
        Duration::from_millis(500),
        tokio::time::sleep(Duration::from_millis(20)),
    )
    .await
    .expect("Timer progress must survive actual native work on two runtime workers");
    let received = tokio::time::timeout(
        Duration::from_millis(500),
        exchange(feed_address, "GET", "/feed", &[]),
    )
    .await
    .expect("Actual feed transport must progress while the authority operation is in flight");
    assert_eq!(received, feed);
    assert!(
        !reading.is_finished(),
        "Transport progress must precede the native operation's final cut"
    );
    let handle = host.handle.clone();
    let installation =
        tokio::spawn(async move { handle.complete_feed(refresh.id(), received, false).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        !installation.is_finished(),
        "The serial Charter install must remain behind the real proof operation"
    );
    let Output::Search(result) = reading.await.unwrap().unwrap().response else {
        panic!("Actual cached native read must succeed")
    };
    assert!(result.entries.is_empty());
    installation.await.unwrap().unwrap();
    let Output::Settings(settings) = call(host.address, Request::Settings(SettingsInput {}))
        .await
        .unwrap()
        .response
    else {
        panic!("Current signed policy must be readable")
    };
    assert_eq!(settings.revision, 2);
    assert_eq!(settings.policy_epoch, native.material.policy_epoch);
    network.abort();
    let _ = network.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forced_actor_shutdown_cancels_and_reaps_actual_native_owner_and_fences_http() {
    if std::env::var_os("CBLC_RECORD_EPOCH_FIXTURE").is_none() {
        eprintln!(
            "skipped: CBLC_RECORD_EPOCH_FIXTURE is required (genuine retained CBLC four-artifact fixture)"
        );
        return;
    }
    let native = Fixture::load();
    let g1 = G1::new(&native, &member(), 1, 10_000).await;
    let delay = Delay::new();
    let mut host = Host::new(&native, delay.executable.clone()).await;
    let enter = entry(&host, &native, &g1).await;
    assert!(matches!(
        call(host.address, enter).await.unwrap().response,
        Output::Enter(_)
    ));
    // A second genuine challenge is independently signed; cancellation happens
    // during the actual proof operation, before it can consume this pending row.
    let request = entry(&host, &native, &g1).await;
    let Request::Enter(input) = &request else {
        unreachable!()
    };
    let challenge: cswb::Challenge = serde_json::from_slice(&input.challenge).unwrap();
    let pending_key = format!(
        "challenge_{}",
        data_encoding::HEXLOWER.encode(&challenge.token)
    );
    let pending = host.storage.get(&pending_key).await.unwrap().unwrap();
    assert_ne!(pending.value, [0]);
    delay.seconds(60);
    let address = host.address;
    let request = tokio::spawn(async move { call(address, request).await });
    let pid = delay.started().await;
    assert!(std::path::Path::new(&format!("/proc/{pid}")).exists());
    // Exact forced-production ordering: shared store fence, one-way native
    // cancellation, actor abort, then mandatory wait for the owned process reap.
    host.storage.close();
    host.cancellation.cancel();
    host.actor.abort();
    let result = tokio::time::timeout(Duration::from_secs(3), &mut host.actor)
        .await
        .expect("Cancelled native work must not retain the actor until its sixty-second delay");
    assert!(result.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(3), async {
        while std::path::Path::new(&format!("/proc/{pid}")).exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("The exact actual native child must be killed and reaped");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), request)
            .await
            .unwrap()
            .unwrap(),
        Err(ErrorCode::AuthorityUnavailable)
    );
    assert!(matches!(
        host.storage.get(&pending_key).await,
        Err(cmmr::Error::Closed)
    ));
    assert_eq!(
        call(host.address, Request::Settings(SettingsInput {})).await,
        Err(ErrorCode::AuthorityUnavailable)
    );
}
