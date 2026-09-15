mod common;
use cfrm::{admission::verify_admission, board::{BoardLimits, MeetingBoard, OnionEndpoint, PresenceUpdate}, Error};
use common::{encoded, member_id, onion, Fixture};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer, SigningKey};

fn limits() -> BoardLimits { BoardLimits { max_members: 2, max_devices_per_member: 2, max_lease_seconds: 60, max_replay_entries: 8 } }
fn update(f: &Fixture, key: &SigningKey, member: u8, sequence: u64, endpoint: bool) -> PresenceUpdate {
    let mut value = PresenceUpdate { community_id: f.trust.community_id.clone(), member_id: member_id(member), chat_public_key: BASE64URL_NOPAD.encode(&key.verifying_key().to_bytes()), sequence, issued_at: 110, expires_at: 150, endpoint: endpoint.then(|| OnionEndpoint { host: onion(), port: 443 }), signature: String::new() };
    sign(&mut value, key); value
}
fn sign(value: &mut PresenceUpdate, key: &SigningKey) {
    let bytes = serde_json::to_vec(&serde_json::json!(["cfrm.presence.v1", value.community_id, value.member_id, value.chat_public_key, value.sequence, value.issued_at, value.expires_at, value.endpoint])).unwrap();
    value.signature = BASE64URL_NOPAD.encode(&key.sign(&bytes).to_bytes());
}

#[test]
fn verifies_external_eligibility_and_rejects_issuer_substitution() {
    let f = Fixture::new(); let grant = f.grant(5, &f.device);
    assert_eq!(verify_admission(&grant, &f.trust, 110), Ok(()));
    let mut forged = grant.clone(); forged.member_id = encoded(6);
    assert_eq!(verify_admission(&forged, &f.trust, 110), Err(Error::Admission));
    assert_eq!(verify_admission(&grant, &f.trust, 1000), Err(Error::Admission));
    let mut trust = f.trust.clone(); trust.issuer_public_key = SigningKey::from_bytes(&[9;32]).verifying_key().to_bytes();
    assert_eq!(verify_admission(&grant, &trust, 110), Err(Error::Admission));
}

#[test]
fn one_member_has_multiple_devices_and_one_identical_public_snapshot() {
    let f = Fixture::new(); let second = SigningKey::from_bytes(&[7; 32]);
    let mut board = MeetingBoard::new(f.trust.clone(), limits()).unwrap();
    board.apply(&f.grant(5,&f.device), &f.authorize(5,&f.device), &update(&f,&f.device,5,1,true), 110).unwrap();
    board.apply(&f.grant(5,&second), &f.authorize(5,&second), &update(&f,&second,5,1,true), 110).unwrap();
    let snapshot = board.snapshot(111).unwrap();
    assert_eq!(snapshot.len(), 1); assert_eq!(snapshot[0].devices.len(), 2);
    assert_eq!(snapshot, board.snapshot(111).unwrap());
    assert!(board.snapshot(150).unwrap().is_empty());
}

#[test]
fn device_signature_binds_member_route_and_entire_update() {
    let f = Fixture::new(); let grant = f.grant(5,&f.device);
    let mut board = MeetingBoard::new(f.trust.clone(), limits()).unwrap();
    let mut forged = update(&f,&f.device,5,1,true); forged.endpoint.as_mut().unwrap().port = 80;
    assert_eq!(board.apply(&grant,&f.authorize(5,&f.device),&forged,110), Err(Error::Signature));
    let mut wrong = update(&f,&f.device,6,1,true); sign(&mut wrong,&f.device);
    assert_eq!(board.apply(&grant,&f.authorize(5,&f.device),&wrong,110), Err(Error::Admission));
    assert!(board.snapshot(110).unwrap().is_empty());
}

#[test]
fn disconnect_keeps_sequence_floor_until_old_leases_expire() {
    let f = Fixture::new(); let grant=f.grant(5,&f.device);
    let mut board=MeetingBoard::new(f.trust.clone(),limits()).unwrap();
    let old=update(&f,&f.device,5,1,true);
    board.apply(&grant,&f.authorize(5,&f.device),&old,110).unwrap();
    let mut offline=update(&f,&f.device,5,2,false); offline.expires_at=120; sign(&mut offline,&f.device);
    board.apply(&grant,&f.authorize(5,&f.device),&offline,111).unwrap();
    assert!(board.snapshot(121).unwrap().is_empty());
    assert_eq!(board.apply(&grant,&f.authorize(5,&f.device),&old,121),Err(Error::Replay));
}

#[test]
fn bounds_devices_members_time_and_validates_onions_before_publication() {
    let f=Fixture::new(); let grant=f.grant(5,&f.device);
    let mut board=MeetingBoard::new(f.trust.clone(),limits()).unwrap();
    let mut bad=update(&f,&f.device,5,1,true); bad.endpoint.as_mut().unwrap().host="https://tracker.example".into(); sign(&mut bad,&f.device);
    assert_eq!(board.apply(&grant,&f.authorize(5,&f.device),&bad,110),Err(Error::InvalidInput));
    let valid=update(&f,&f.device,5,1,true); board.apply(&grant,&f.authorize(5,&f.device),&valid,110).unwrap();
    assert_eq!(board.snapshot(109),Err(Error::ClockRollback));
    for seed in [7,8] { let key=SigningKey::from_bytes(&[seed;32]); let result=board.apply(&f.grant(5,&key),&f.authorize(5,&key),&update(&f,&key,5,1,true),111); assert_eq!(result, if seed==7 {Ok(())} else {Err(Error::Capacity)}); }
}

#[test]
fn suspicious_eligibility_issuer_cannot_authorize_a_new_device_as_somebody_else() {
    let f = Fixture::new(); let attacker = SigningKey::from_bytes(&[8;32]);
    let grant = f.grant(5,&attacker); // Genuine issuer signature: issuer is hostile.
    let mut forged = f.authorize(8,&attacker); forged.member_id = member_id(5);
    let mut board = MeetingBoard::new(f.trust.clone(),limits()).unwrap();
    assert_eq!(board.apply(&grant,&forged,&update(&f,&attacker,5,1,true),110),Err(Error::Admission));
    assert!(board.snapshot(110).unwrap().is_empty());
}

#[test]
fn snapshot_preserves_signed_rows_for_independent_recipient_verification() {
    let f=Fixture::new(); let mut board=MeetingBoard::new(f.trust.clone(),limits()).unwrap();
    board.apply(&f.grant(5,&f.device),&f.authorize(5,&f.device),&update(&f,&f.device,5,1,true),110).unwrap();
    let snapshot=board.snapshot(111).unwrap();let row=&snapshot[0].devices[0];
    cfrm::board::verify_presence(&row.admission,&row.authorization,&row.update,&f.trust,60,111).unwrap();
    let mut tampered=row.update.clone();tampered.endpoint.as_mut().unwrap().port=80;
    assert_eq!(cfrm::board::verify_presence(&row.admission,&row.authorization,&tampered,&f.trust,60,111),Err(Error::Signature));
}
