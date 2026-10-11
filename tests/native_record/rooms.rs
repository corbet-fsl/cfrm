//! Same genuine HTTP native entry, original blinded issuance and anonymous wire.
use super::*;
use cgth::cmbl;

fn possession(session: &[u8], nonce: u8) -> Possession {
    Possession {
        session: session.to_vec(),
        request_nonce: vec![nonce; 16],
        signature: vec![],
    }
}
fn signed(g1: &G1, mut request: Request) -> Request {
    let proof = request.possession().unwrap();
    let session: cswb::Session = serde_json::from_slice(&proof.session).unwrap();
    let nonce = proof.request_nonce.as_slice().try_into().unwrap();
    let signature = g1
        .device
        .sign(&cswb::request_message(
            g1::ORIGIN,
            request.info().name,
            &session,
            nonce,
            &request.unsigned_bytes().unwrap(),
        ))
        .to_bytes()
        .to_vec();
    request.possession_mut().unwrap().signature = signature;
    request
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_http_blind_issuance_connect_order_and_expiry_preserve_anonymous_boundary() {
    let native = Fixture::load();
    let g1 = G1::new(&native, &member(), 1, 10_000).await;
    let delay = Delay::new();
    let host = Host::new(&native, delay.executable.clone()).await;
    let request = entry(&host, &native, &g1).await;
    let Output::Enter(entry) = call(host.address, request).await.unwrap().response else {
        panic!("Actual native member entry required")
    };
    let request = signed(
        &g1,
        Request::RoomEpoch(RoomEpochInput {
            possession: possession(&entry.session, 1),
        }),
    );
    let Output::RoomEpoch(common) = call(host.address, request).await.unwrap().response else {
        panic!("Actual common owner epoch required")
    };
    let epoch: cmbl::passes::Epoch = serde_json::from_slice(&common.epoch).unwrap();
    assert_eq!(epoch.valid_until, (native.now + 3) * 1000);
    let prepared = cmbl::passes::PreparedPass::new(&epoch, [8; 16], native.now * 1000).unwrap();
    let request = signed(
        &g1,
        Request::RoomIssue(RoomIssueInput {
            possession: possession(&entry.session, 2),
            operation: vec![9; 16],
            blinded_request: serde_json::to_vec(&prepared.request()).unwrap(),
        }),
    );
    let Output::RoomIssue(issued) = call(host.address, request).await.unwrap().response else {
        panic!("Actual blind signature required")
    };
    let pass = prepared
        .finalize(&issued.signature, native.now * 1000)
        .unwrap();
    let depart = signed(
        &g1,
        Request::Depart(DepartInput {
            possession: possession(&entry.session, 3),
        }),
    );
    assert!(matches!(
        call(host.address, depart).await.unwrap().response,
        Output::Depart(_)
    ));
    let command = cmbl::Request {
        room: [8; 16],
        operation: [10; 16],
        action: cmbl::Action::Connect {
            connection: pass.connection(),
        },
    };
    let input = RoomInput {
        room_pass: pass
            .prove(&command, &common.incarnation, native.now * 1000)
            .unwrap(),
        command: serde_json::to_vec(&command).unwrap(),
    };
    // A valid anonymous proof cannot select a different command route.
    assert_eq!(
        call(host.address, Request::RoomOrder(input.clone())).await,
        Err(ErrorCode::InvalidRequest)
    );
    let Output::RoomConnect(connected) = call(host.address, Request::RoomConnect(input.clone()))
        .await
        .unwrap()
        .response
    else {
        panic!("Actual anonymous room required")
    };
    let outcome: cmbl::Outcome = serde_json::from_slice(&connected.result).unwrap();
    assert_eq!(outcome.active_connections, 1);
    let order = cmbl::Request {
        room: [8; 16],
        operation: [11; 16],
        action: cmbl::Action::Order {
            expected: outcome.counter,
            ciphertext: vec![17, 18],
        },
    };
    let order = RoomInput {
        room_pass: pass
            .prove(&order, &common.incarnation, native.now * 1000)
            .unwrap(),
        command: serde_json::to_vec(&order).unwrap(),
    };
    let Output::RoomOrder(ordered) = call(host.address, Request::RoomOrder(order))
        .await
        .unwrap()
        .response
    else {
        panic!("Actual anonymous order required")
    };
    let ordered: cmbl::Outcome = serde_json::from_slice(&ordered.result).unwrap();
    assert_eq!(ordered.counter, outcome.counter + 1);
    assert_eq!(
        call(host.address, Request::RoomHandover(input.clone())).await,
        Err(ErrorCode::AuthorityUnavailable)
    );
    host.clock.0.store(epoch.valid_until, Ordering::SeqCst);
    assert_eq!(
        call(host.address, Request::RoomConnect(input)).await,
        Err(ErrorCode::AuthorityUnavailable)
    );
}
