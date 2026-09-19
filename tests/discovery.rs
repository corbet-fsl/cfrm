mod common;
use cfrm::{discovery::*, Error};
use common::{encoded, Fixture};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

struct RecordingStore(Arc<AtomicUsize>);
impl DiscoveryStore for RecordingStore {
    fn execute(
        &self,
        _: &VerifiedDiscoveryRequest,
        _: &DiscoveryLimits,
        _: u64,
    ) -> Result<DiscoveryResponse, Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(DiscoveryResponse::Updated)
    }
}

fn limits() -> DiscoveryLimits {
    DiscoveryLimits {
        max_request_bytes: 16384,
        max_record_bytes: 8192,
        max_response_bytes: 32768,
        max_ciphertext_bytes: 1024,
        max_discriminator_bytes: 100,
        max_profile_ttl_seconds: 600,
        max_lease_seconds: 60,
        max_request_seconds: 20,
        max_members: 100,
        max_devices_per_member: 4,
        max_replay_entries: 1000,
        max_results: 20,
        max_scan: 100,
        publish_limit: 2,
        publish_window_seconds: 86400,
        discriminator_limit: 1,
        discriminator_window_seconds: 86400,
        read_limit: 100,
        read_window_seconds: 60,
        registry: BTreeMap::from([
            (
                "ageBand".into(),
                DiscriminatorDomain::Range {
                    minimum: 3,
                    maximum: 20,
                },
            ),
            (
                "intent".into(),
                DiscriminatorDomain::Enum {
                    values: vec![0, 1, 2],
                },
            ),
        ]),
    }
}

fn envelope_bytes(e: &ProfileEnvelope) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([
        "cfrm.cached-profile.v1",
        e.community_id,
        e.member_id,
        e.chat_public_key,
        e.profile_epoch,
        e.sequence,
        e.issued_at,
        e.expires_at,
        e.nonce,
        e.profile_digest,
        e.discriminators.iter().collect::<Vec<_>>()
    ]))
    .unwrap()
}

fn sign_request(f: &Fixture, r: &mut DiscoveryRequest) {
    sign_with(&f.device, r);
}

fn sign_with(key: &SigningKey, r: &mut DiscoveryRequest) {
    let bytes = serde_json::to_vec(&serde_json::json!([
        "cfrm.discovery-request.v1",
        r.admission.community_id,
        r.admission.policy_digest,
        r.admission.member_id,
        r.admission.chat_public_key,
        r.session_id,
        r.request_id,
        r.issued_at,
        r.expires_at,
        serde_json::to_value(&r.operation).unwrap()
    ]))
    .unwrap();
    r.signature = BASE64URL_NOPAD.encode(&key.sign(&bytes).to_bytes());
}

fn operation(
    f: &Fixture,
    key: &SigningKey,
    member: u8,
    session: u8,
    id: u8,
    now: u64,
    operation: DiscoveryOperation,
) -> DiscoveryRequest {
    let mut r = DiscoveryRequest {
        version: 1,
        admission: f.grant(member, key),
        authorization: f.authorize(member, key),
        session_id: encoded(session),
        request_id: encoded(id),
        issued_at: now,
        expires_at: now + 20,
        operation,
        signature: String::new(),
    };
    sign_with(key, &mut r);
    r
}

fn fetch(f: &Fixture, id: u8, now: u64) -> DiscoveryRequest {
    operation(
        f,
        &f.device,
        5,
        11,
        id,
        now,
        DiscoveryOperation::Fetch {
            member_id: common::member_id(5),
        },
    )
}

#[test]
fn actual_store_publication_is_idempotent_and_reads_do_not_replay() {
    use cfrm::discovery_store::MemoryDiscoveryStore;
    let f = Fixture::new();
    let service =
        DiscoveryService::new(f.trust.clone(), limits(), MemoryDiscoveryStore::new()).unwrap();
    let r = request(&f);
    assert_eq!(service.execute(&r, 110), Ok(DiscoveryResponse::Updated));
    assert_eq!(service.execute(&r, 110), Ok(DiscoveryResponse::Updated));
    assert!(matches!(
        service.execute(&fetch(&f, 30, 110), 110),
        Ok(DiscoveryResponse::Profile {
            publication: Some(_)
        })
    ));
    assert_eq!(
        service.execute(&fetch(&f, 30, 110), 110),
        Err(Error::Replay)
    );
    let query = operation(
        &f,
        &f.device,
        5,
        11,
        31,
        110,
        DiscoveryOperation::Query {
            filters: BTreeMap::new(),
            limit: 1,
            after: None,
        },
    );
    match service.execute(&query, 110).unwrap() {
        DiscoveryResponse::Page {
            entries,
            next_cursor,
        } => {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].member_id, common::member_id(5));
            assert_eq!(entries[0].expires_at, 170);
            assert!(next_cursor.is_none());
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn expired_outer_request_recovers_identical_current_profile_without_quota_or_expiry_reset() {
    use cfrm::discovery_store::MemoryDiscoveryStore;
    let f = Fixture::new();
    let mut l = limits();
    l.publish_limit = 1;
    let service = DiscoveryService::new(f.trust.clone(), l, MemoryDiscoveryStore::new()).unwrap();
    let original = request(&f);
    service.execute(&original, 110).unwrap();
    assert_eq!(service.execute(&original, 131), Err(Error::Expired));
    let mut repair = original.clone();
    repair.request_id = encoded(64);
    repair.issued_at = 131;
    repair.expires_at = 151;
    if let DiscoveryOperation::Publish { lease, .. } = &mut repair.operation {
        lease.sequence = 2;
        lease.expires_at = 191;
    }
    sign_request(&f, &mut repair);
    service.execute(&repair, 131).unwrap();
    match service.execute(&fetch(&f, 65, 131), 131).unwrap() {
        DiscoveryResponse::Profile {
            publication: Some(p),
        } => {
            assert_eq!(p.envelope.sequence, 1);
            assert_eq!(p.envelope.expires_at, 400);
        }
        other => panic!("unexpected {other:?}"),
    }
    let mut stale_lease = repair.clone();
    stale_lease.request_id = encoded(66);
    sign_request(&f, &mut stale_lease);
    assert_eq!(service.execute(&stale_lease, 131), Err(Error::Replay));
    let mut distinct = repair;
    distinct.request_id = encoded(67);
    if let DiscoveryOperation::Publish { lease, publication } = &mut distinct.operation {
        lease.sequence = 3;
        publication.envelope.sequence = 2;
        publication.envelope.profile_epoch = encoded(68);
        publication.envelope.signature = BASE64URL_NOPAD.encode(
            &f.device
                .sign(&envelope_bytes(&publication.envelope))
                .to_bytes(),
        );
    }
    sign_request(&f, &mut distinct);
    assert_eq!(service.execute(&distinct, 131), Err(Error::Capacity));
}

#[test]
fn independent_devices_keep_member_visible_until_final_lease_expires() {
    use cfrm::discovery_store::MemoryDiscoveryStore;
    let f = Fixture::new();
    let second = SigningKey::from_bytes(&[42; 32]);
    let service =
        DiscoveryService::new(f.trust.clone(), limits(), MemoryDiscoveryStore::new()).unwrap();
    service.execute(&request(&f), 110).unwrap();
    let heartbeat = operation(
        &f,
        &second,
        5,
        22,
        32,
        110,
        DiscoveryOperation::Heartbeat {
            lease: DiscoveryLease {
                lease_id: encoded(22),
                sequence: 1,
                expires_at: 160,
            },
        },
    );
    service.execute(&heartbeat, 110).unwrap();
    let disconnect = operation(
        &f,
        &f.device,
        5,
        11,
        33,
        111,
        DiscoveryOperation::Disconnect {
            lease_id: encoded(11),
            sequence: 2,
        },
    );
    service.execute(&disconnect, 111).unwrap();
    assert!(matches!(
        service.execute(&fetch(&f, 34, 159), 159),
        Ok(DiscoveryResponse::Profile {
            publication: Some(_)
        })
    ));
    assert_eq!(
        service.execute(&fetch(&f, 35, 160), 160),
        Ok(DiscoveryResponse::Profile { publication: None })
    );
    let late_heartbeat = operation(
        &f,
        &second,
        5,
        22,
        36,
        160,
        DiscoveryOperation::Heartbeat {
            lease: DiscoveryLease {
                lease_id: encoded(22),
                sequence: 2,
                expires_at: 200,
            },
        },
    );
    service.execute(&late_heartbeat, 160).unwrap();
    // TTL expiry removed the only ciphertext slot. Heartbeats carry no blob,
    // so they cannot resurrect bytes that disappeared while every device was off.
    assert_eq!(
        service.execute(&fetch(&f, 37, 160), 160),
        Ok(DiscoveryResponse::Profile { publication: None })
    );
}

#[test]
fn stale_heartbeat_and_disconnect_cannot_revive_or_replace_new_device_session() {
    use cfrm::discovery_store::MemoryDiscoveryStore;
    let f = Fixture::new();
    let service =
        DiscoveryService::new(f.trust.clone(), limits(), MemoryDiscoveryStore::new()).unwrap();
    service.execute(&request(&f), 110).unwrap();
    let replace = operation(
        &f,
        &f.device,
        5,
        23,
        40,
        111,
        DiscoveryOperation::Heartbeat {
            lease: DiscoveryLease {
                lease_id: encoded(23),
                sequence: 2,
                expires_at: 170,
            },
        },
    );
    service.execute(&replace, 111).unwrap();
    let stale = operation(
        &f,
        &f.device,
        5,
        11,
        41,
        111,
        DiscoveryOperation::Disconnect {
            lease_id: encoded(11),
            sequence: 3,
        },
    );
    assert_eq!(service.execute(&stale, 111), Err(Error::Replay));
    let stale = operation(
        &f,
        &f.device,
        5,
        11,
        42,
        111,
        DiscoveryOperation::Heartbeat {
            lease: DiscoveryLease {
                lease_id: encoded(11),
                sequence: 1,
                expires_at: 169,
            },
        },
    );
    assert_eq!(service.execute(&stale, 111), Err(Error::Replay));
    assert!(matches!(
        service.execute(&fetch(&f, 43, 111), 111),
        Ok(DiscoveryResponse::Profile {
            publication: Some(_)
        })
    ));
}

#[test]
fn shared_member_quotas_reject_device_and_session_rotation_bypasses() {
    use cfrm::discovery_store::MemoryDiscoveryStore;
    let f = Fixture::new();
    let second = SigningKey::from_bytes(&[42; 32]);
    let mut l = limits();
    l.read_limit = 1;
    let service = DiscoveryService::new(f.trust.clone(), l, MemoryDiscoveryStore::new()).unwrap();
    service.execute(&request(&f), 110).unwrap();
    service.execute(&fetch(&f, 44, 110), 110).unwrap();
    let rotated = operation(
        &f,
        &second,
        5,
        24,
        45,
        110,
        DiscoveryOperation::Fetch {
            member_id: common::member_id(5),
        },
    );
    assert_eq!(service.execute(&rotated, 110), Err(Error::Capacity));
}

#[test]
fn same_revision_concurrent_distinct_publications_commit_exactly_one() {
    use cfrm::discovery_store::MemoryDiscoveryStore;
    use std::sync::Barrier;
    let f = Fixture::new();
    let service = Arc::new(
        DiscoveryService::new(f.trust.clone(), limits(), MemoryDiscoveryStore::new()).unwrap(),
    );
    let first = request(&f);
    let mut second = request(&f);
    second.request_id = encoded(60);
    edit_profile(&mut second, |e| {
        let ciphertext = [61; 32];
        e.ciphertext = BASE64URL_NOPAD.encode(&ciphertext);
        e.profile_digest = BASE64URL_NOPAD.encode(&Sha256::digest(ciphertext));
        e.signature = BASE64URL_NOPAD.encode(&f.device.sign(&envelope_bytes(e)).to_bytes());
    });
    sign_request(&f, &mut second);
    let barrier = Arc::new(Barrier::new(2));
    let jobs: Vec<_> = [first, second]
        .into_iter()
        .map(|r| {
            let service = service.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                service.execute(&r, 110)
            })
        })
        .collect();
    let results: Vec<_> = jobs.into_iter().map(|j| j.join().unwrap()).collect();
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == Ok(DiscoveryResponse::Updated))
            .count(),
        1
    );
    assert_eq!(
        results.iter().filter(|r| **r == Err(Error::Replay)).count(),
        1
    );
}

#[test]
fn closed_discriminator_quota_rejects_even_fully_signed_republication() {
    use cfrm::discovery_store::MemoryDiscoveryStore;
    let f = Fixture::new();
    let service =
        DiscoveryService::new(f.trust.clone(), limits(), MemoryDiscoveryStore::new()).unwrap();
    service.execute(&request(&f), 110).unwrap();
    let mut update = request(&f);
    update.request_id = encoded(62);
    if let DiscoveryOperation::Publish { lease, publication } = &mut update.operation {
        lease.sequence = 2;
        publication.envelope.sequence = 2;
        publication
            .envelope
            .discriminators
            .insert("ageBand".into(), 7);
        publication.envelope.signature = BASE64URL_NOPAD.encode(
            &f.device
                .sign(&envelope_bytes(&publication.envelope))
                .to_bytes(),
        );
    }
    sign_request(&f, &mut update);
    assert_eq!(service.execute(&update, 110), Err(Error::Capacity));
    match service.execute(&fetch(&f, 63, 110), 110).unwrap() {
        DiscoveryResponse::Profile {
            publication: Some(p),
        } => assert_eq!(p.envelope.discriminators["ageBand"], 6),
        other => panic!("unexpected {other:?}"),
    }
}

fn request(f: &Fixture) -> DiscoveryRequest {
    let admission = f.grant(5, &f.device);
    let authorization = f.authorize(5, &f.device);
    let cipher = [15; 32];
    let mut envelope = ProfileEnvelope {
        version: 1,
        community_id: admission.community_id.clone(),
        member_id: admission.member_id.clone(),
        chat_public_key: admission.chat_public_key.clone(),
        profile_epoch: encoded(13),
        sequence: 1,
        issued_at: 110,
        expires_at: 400,
        nonce: BASE64URL_NOPAD.encode(&[14; 12]),
        profile_digest: BASE64URL_NOPAD.encode(&Sha256::digest(cipher)),
        discriminators: BTreeMap::from([("ageBand".into(), 6)]),
        ciphertext: BASE64URL_NOPAD.encode(&cipher),
        signature: String::new(),
    };
    envelope.signature =
        BASE64URL_NOPAD.encode(&f.device.sign(&envelope_bytes(&envelope)).to_bytes());
    let mut r = DiscoveryRequest {
        version: 1,
        admission: admission.clone(),
        authorization: authorization.clone(),
        session_id: encoded(11),
        request_id: encoded(12),
        issued_at: 110,
        expires_at: 130,
        operation: DiscoveryOperation::Publish {
            publication: CachedProfile {
                admission,
                authorization,
                envelope,
            },
            lease: DiscoveryLease {
                lease_id: encoded(11),
                sequence: 1,
                expires_at: 170,
            },
        },
        signature: String::new(),
    };
    sign_request(f, &mut r);
    r
}

fn setup() -> (Fixture, DiscoveryService<RecordingStore>, Arc<AtomicUsize>) {
    let f = Fixture::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let service =
        DiscoveryService::new(f.trust.clone(), limits(), RecordingStore(calls.clone())).unwrap();
    (f, service, calls)
}

fn edit_profile(r: &mut DiscoveryRequest, edit: impl FnOnce(&mut ProfileEnvelope)) {
    if let DiscoveryOperation::Publish { publication, .. } = &mut r.operation {
        edit(&mut publication.envelope);
    }
}

#[test]
fn valid_certified_ciphertext_reaches_storage_once() {
    let (f, service, calls) = setup();
    let r = request(&f);
    assert_eq!(
        service.execute_bytes(&serde_json::to_vec(&r).unwrap(), 110),
        Ok(DiscoveryResponse::Updated)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    if let DiscoveryOperation::Publish { publication, .. } = &r.operation {
        assert_eq!(
            profile_signing_bytes(&publication.envelope).unwrap(),
            envelope_bytes(&publication.envelope)
        );
        let aad: serde_json::Value =
            serde_json::from_slice(&profile_aad_bytes(&publication.envelope).unwrap()).unwrap();
        assert_eq!(aad[0], "cfrm.cached-profile.aad.v1");
        assert_eq!(aad.as_array().unwrap().len(), 10);
        assert!(
            !String::from_utf8(profile_aad_bytes(&publication.envelope).unwrap())
                .unwrap()
                .contains(&publication.envelope.profile_digest)
        );
        let mut before_encryption = publication.envelope.clone();
        before_encryption.profile_digest.clear();
        assert_eq!(
            profile_aad_bytes(&before_encryption).unwrap(),
            profile_aad_bytes(&publication.envelope).unwrap()
        );
        assert_eq!(
            profile_signing_bytes(&before_encryption),
            Err(Error::InvalidInput)
        );
    }
}

#[test]
fn holder_certificate_without_device_possession_never_reaches_store() {
    let (f, service, calls) = setup();
    let mut r = request(&f);
    r.signature = BASE64URL_NOPAD.encode(&[0; 64]);
    assert_eq!(service.execute(&r, 110), Err(Error::Signature));
    let mut r = request(&f);
    r.authorization.root_public_key = encoded(77);
    assert_eq!(service.execute(&r, 110), Err(Error::Admission));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn outer_signature_binds_operation_session_and_scope() {
    let (f, service, calls) = setup();
    for changed in 0..4 {
        let mut r = request(&f);
        match changed {
            0 => {
                r.operation = DiscoveryOperation::Fetch {
                    member_id: encoded(55),
                }
            }
            1 => r.session_id = encoded(56),
            2 => r.request_id = encoded(57),
            _ => r.expires_at = 129,
        }
        assert_eq!(service.execute(&r, 110), Err(Error::Signature));
    }
    let mut r = request(&f);
    r.admission.community_id = "other.example".into();
    sign_request(&f, &mut r);
    assert_eq!(service.execute(&r, 110), Err(Error::Admission));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn profile_filter_ciphertext_and_owner_mix_and_match_is_rejected() {
    let (f, service, calls) = setup();
    for change in 0..4 {
        let mut r = request(&f);
        edit_profile(&mut r, |e| match change {
            0 => {
                e.discriminators.insert("ageBand".into(), 7);
            }
            1 => {
                e.ciphertext = BASE64URL_NOPAD.encode(&[17; 32]);
            }
            2 => {
                e.member_id = encoded(18);
            }
            _ => {
                e.profile_epoch = encoded(19);
            }
        });
        sign_request(&f, &mut r);
        assert!(service.execute(&r, 110).is_err());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn signed_unsupported_discriminators_and_out_of_domain_values_are_rejected() {
    let (f, service, calls) = setup();
    for (name, value) in [("text", 1), ("ageBand", 2), ("ageBand", 21), ("intent", 3)] {
        let mut r = request(&f);
        edit_profile(&mut r, |e| {
            e.discriminators = BTreeMap::from([(name.into(), value)]);
            e.signature = BASE64URL_NOPAD.encode(&f.device.sign(&envelope_bytes(e)).to_bytes());
        });
        sign_request(&f, &mut r);
        assert_eq!(service.execute(&r, 110), Err(Error::InvalidInput));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn profile_digest_cannot_substitute_for_ciphertext_bytes_or_bound() {
    let (f, service, calls) = setup();
    for n in [0, 15, 1025] {
        let mut r = request(&f);
        edit_profile(&mut r, |e| {
            let cipher = vec![7; n];
            e.ciphertext = BASE64URL_NOPAD.encode(&cipher);
            e.profile_digest = BASE64URL_NOPAD.encode(&Sha256::digest(&cipher));
            e.signature = BASE64URL_NOPAD.encode(&f.device.sign(&envelope_bytes(e)).to_bytes());
        });
        sign_request(&f, &mut r);
        assert!(service.execute(&r, 110).is_err());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn lease_and_request_lifetimes_are_bounded_by_owner_authority() {
    let (f, service, calls) = setup();
    assert_eq!(service.execute(&request(&f), 130), Err(Error::Expired));
    assert_eq!(service.execute(&request(&f), 109), Err(Error::Expired));
    for expiry in [110, 171, 901] {
        let mut r = request(&f);
        if let DiscoveryOperation::Publish { lease, .. } = &mut r.operation {
            lease.expires_at = expiry;
        }
        sign_request(&f, &mut r);
        assert_eq!(service.execute(&r, 110), Err(Error::Expired));
    }
    let mut r = request(&f);
    r.operation = DiscoveryOperation::Disconnect {
        lease_id: encoded(99),
        sequence: 2,
    };
    sign_request(&f, &mut r);
    assert_eq!(service.execute(&r, 110), Err(Error::InvalidInput));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn unknown_fields_and_oversized_input_fail_before_store() {
    let (f, service, calls) = setup();
    let r = request(&f);
    let mut value = serde_json::to_value(&r).unwrap();
    value["verified"] = serde_json::json!(true);
    assert_eq!(
        service.execute_bytes(&serde_json::to_vec(&value).unwrap(), 110),
        Err(Error::InvalidInput)
    );
    let mut value = serde_json::to_value(&r).unwrap();
    value["operation"]["publication"]["envelope"]["text"] = serde_json::json!("plaintext");
    assert_eq!(
        service.execute_bytes(&serde_json::to_vec(&value).unwrap(), 110),
        Err(Error::InvalidInput)
    );
    assert_eq!(
        service.execute_bytes(&vec![b' '; 16385], 110),
        Err(Error::Capacity)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn query_registry_cursor_and_page_limits_are_validated_without_ledger() {
    let (f, service, calls) = setup();
    let mut r = request(&f);
    r.operation = DiscoveryOperation::Query {
        filters: BTreeMap::from([("intent".into(), 2)]),
        limit: 20,
        after: None,
    };
    sign_request(&f, &mut r);
    assert!(service.execute(&r, 110).is_ok());
    for bad in [
        DiscoveryOperation::Query {
            filters: BTreeMap::new(),
            limit: 21,
            after: None,
        },
        DiscoveryOperation::Query {
            filters: BTreeMap::new(),
            limit: 1,
            after: Some("unbounded cursor".into()),
        },
        DiscoveryOperation::Query {
            filters: BTreeMap::from([("extra".into(), 0)]),
            limit: 1,
            after: None,
        },
    ] {
        r.operation = bad;
        sign_request(&f, &mut r);
        assert!(service.execute(&r, 110).is_err());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn query_byte_budget_returns_every_match_once_across_pages() {
    use cfrm::discovery_store::MemoryDiscoveryStore;
    let f = Fixture::new();
    let mut l = limits();
    l.max_record_bytes = 3000;
    l.max_response_bytes = 3000;
    let service = DiscoveryService::new(f.trust.clone(), l, MemoryDiscoveryStore::new()).unwrap();
    let mut expected = Vec::new();
    for member in 5..25 {
        let mut r = request(&f);
        r.admission = f.grant(member, &f.device);
        r.authorization = f.authorize(member, &f.device);
        if let DiscoveryOperation::Publish { publication, .. } = &mut r.operation {
            publication.admission = r.admission.clone();
            publication.authorization = r.authorization.clone();
            publication.envelope.member_id = r.admission.member_id.clone();
            publication.envelope.signature = BASE64URL_NOPAD.encode(
                &f.device
                    .sign(&envelope_bytes(&publication.envelope))
                    .to_bytes(),
            );
        }
        sign_request(&f, &mut r);
        service.execute(&r, 110).unwrap();
        expected.push(common::member_id(member));
    }
    expected.sort();
    let mut after = None;
    let mut received = Vec::new();
    let mut pages = 0;
    loop {
        pages += 1;
        assert!(pages <= 20, "cursor must advance");
        let q = operation(
            &f,
            &f.device,
            5,
            11,
            80 + pages,
            110,
            DiscoveryOperation::Query {
                filters: BTreeMap::new(),
                limit: 20,
                after: after.clone(),
            },
        );
        let response = service.execute(&q, 110).unwrap();
        assert!(serde_json::to_vec(&response).unwrap().len() <= 3000);
        match response {
            DiscoveryResponse::Page {
                entries,
                next_cursor,
            } => {
                assert!(!entries.is_empty());
                received.extend(entries.into_iter().map(|entry| entry.member_id));
                if next_cursor.is_none() {
                    break;
                }
                assert_ne!(next_cursor, after);
                after = next_cursor;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(pages > 1, "fixture must exercise byte pagination");
    assert_eq!(received, expected);
}

#[test]
fn invalid_configuration_has_no_hidden_defaults() {
    let f = Fixture::new();
    for bad in 0..5 {
        let mut l = limits();
        match bad {
            0 => l.read_limit = 0,
            1 => l.max_results = l.max_scan + 1,
            2 => {
                l.registry.insert(
                    "bad-name".into(),
                    DiscriminatorDomain::Enum { values: vec![1] },
                );
            }
            3 => {
                l.registry.insert(
                    "intent".into(),
                    DiscriminatorDomain::Enum { values: vec![1, 1] },
                );
            }
            _ => l.max_record_bytes = l.max_request_bytes + 1,
        }
        assert!(DiscoveryService::new(
            f.trust.clone(),
            l,
            RecordingStore(Arc::new(AtomicUsize::new(0)))
        )
        .is_err());
    }
}

#[cfg(feature = "discovery-api")]
#[tokio::test]
async fn http_route_verifies_real_signatures_and_exact_host_before_storage() {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use cfrm::discovery_api::{router, DiscoveryHttpLimits};
    use tower::ServiceExt;
    let (f, service, calls) = setup();
    let app = router(
        Arc::new(service),
        Arc::new(|| 110),
        DiscoveryHttpLimits {
            max_concurrent_requests: 2,
            body_timeout_millis: 500,
            allowed_hosts: Some(vec!["api.example.test".into()]),
        },
    )
    .unwrap();
    let body = serde_json::to_vec(&request(&f)).unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/discovery")
                .header("host", "API.EXAMPLE.TEST")
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        &to_bytes(response.into_body(), 1024).await.unwrap()[..],
        b"{\"kind\":\"updated\"}"
    );
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/discovery")
                .header("host", "wrong.example.test")
                .header("x-forwarded-host", "api.example.test")
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/discovery")
                .header("host", "api.example.test")
                .header("content-type", "application/json")
                .body(Body::from("{\"verified\":true}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/discovery")
                .header("host", "api.example.test")
                .header("content-type", "application/json")
                .body(Body::from(vec![b'x'; 16385]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let response = app
        .oneshot(
            Request::post("/v1/discovery")
                .header("host", "api.example.test")
                .header("content-type", "text/plain")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
