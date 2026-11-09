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
    let request = entry(&host, &native, &g1).await;
    let Output::Enter(first) = call(host.address, request).await.unwrap().response else {
        panic!("Actual native member entry required")
    };
    let request = signed(
        &g1,
        Request::RoomEpoch(RoomEpochInput {
            possession: possession(&first.session, 1),
        }),
    );
    let Output::RoomEpoch(common) = call(host.address, request).await.unwrap().response else {
        panic!("Actual common owner epoch required")
    };
    let epoch: cmbl::passes::Epoch = serde_json::from_slice(&common.epoch).unwrap();
    assert_eq!(epoch.valid_until, (native.now + 3) * 1000);
    // The opaque room id is derived from the room's own listing key.
    let listing_key = ed25519_dalek::SigningKey::from_bytes(&[41; 32]);
    let room = cmbl::listing::room_id(&listing_key.verifying_key().to_bytes());
    let prepared = cmbl::passes::PreparedPass::new(&epoch, room, native.now * 1000).unwrap();
    let request = signed(
        &g1,
        Request::RoomIssue(RoomIssueInput {
            possession: possession(&first.session, 2),
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
            possession: possession(&first.session, 3),
        }),
    );
    assert!(matches!(
        call(host.address, depart).await.unwrap().response,
        Output::Depart(_)
    ));
    let command = cmbl::Request {
        room,
        operation: [10; 16],
        // An absent room is created only by resuming it; Connect joins a live one.
        action: cmbl::Action::Resume {
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
    let Output::RoomResume(connected) = call(host.address, Request::RoomResume(input.clone()))
        .await
        .unwrap()
        .response
    else {
        panic!("Actual anonymous room required")
    };
    let outcome: cmbl::Outcome = serde_json::from_slice(&connected.result).unwrap();
    assert_eq!(outcome.active_connections, 1);
    let order = cmbl::Request {
        room,
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
    // Listing: any pass holder submits the entry the room key signed; members
    // read it with the here-now count and never traffic volume.
    let listed_entry = |counter, withdrawn| {
        cmbl::listing::SignedEntry::sign(
            cmbl::listing::Entry {
                key: listing_key.verifying_key().to_bytes(),
                name: "Chess".into(),
                description: "Friendly games".into(),
                counter,
                expires_ms: (native.now + 3) * 1000,
                withdrawn,
            },
            &listing_key,
        )
        .unwrap()
    };
    let publish = |operation: u8, entry| {
        let command = cmbl::Request {
            room,
            operation: [operation; 16],
            action: cmbl::Action::Publish { entry },
        };
        RoomInput {
            room_pass: pass
                .prove(&command, &common.incarnation, native.now * 1000)
                .unwrap(),
            command: serde_json::to_vec(&command).unwrap(),
        }
    };
    assert_eq!(
        call(
            host.address,
            Request::RoomConnect(publish(14, listed_entry(1, false)))
        )
        .await,
        Err(ErrorCode::InvalidRequest)
    );
    let Output::RoomPublish(_) = call(
        host.address,
        Request::RoomPublish(publish(12, listed_entry(1, false))),
    )
    .await
    .unwrap()
    .response
    else {
        panic!("Actual signed listing required")
    };
    let request = entry(&host, &native, &g1).await;
    let Output::Enter(second) = call(host.address, request).await.unwrap().response else {
        panic!("Actual second native member entry required")
    };
    let list = |nonce| {
        signed(
            &g1,
            Request::RoomList(RoomListInput {
                possession: possession(&second.session, nonce),
                cursor: None,
                page_size: 4,
            }),
        )
    };
    let Output::RoomList(listing) = call(host.address, list(1)).await.unwrap().response else {
        panic!("Actual room listing required")
    };
    assert_eq!(listing.rooms.len(), 1);
    assert_eq!(listing.rooms[0].room, room.to_vec());
    assert_eq!(listing.rooms[0].name, "Chess");
    assert_eq!(listing.rooms[0].here_now, 1);
    let Output::RoomPublish(_) = call(
        host.address,
        Request::RoomPublish(publish(13, listed_entry(2, true))),
    )
    .await
    .unwrap()
    .response
    else {
        panic!("Actual signed tombstone required")
    };
    let Output::RoomList(listing) = call(host.address, list(2)).await.unwrap().response else {
        panic!("Actual room listing required")
    };
    assert!(listing.rooms.is_empty());
    host.clock.0.store(epoch.valid_until, Ordering::SeqCst);
    assert_eq!(
        call(host.address, Request::RoomResume(input)).await,
        Err(ErrorCode::AuthorityUnavailable)
    );
}
