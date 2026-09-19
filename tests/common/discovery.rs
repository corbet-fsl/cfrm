#![allow(dead_code)]
use crate::common::{encoded, member_id, Fixture};
use cfrm::discovery::*;
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub fn limits() -> DiscoveryLimits {
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
        registry: BTreeMap::from([(
            "ageBand".into(),
            DiscriminatorDomain::Range {
                minimum: 3,
                maximum: 20,
            },
        )]),
    }
}

pub fn sign(key: &SigningKey, request: &mut DiscoveryRequest) {
    request.signature = BASE64URL_NOPAD.encode(
        &key.sign(&request_signing_bytes(request).unwrap())
            .to_bytes(),
    );
}

pub fn operation(
    f: &Fixture,
    key: &SigningKey,
    member: u8,
    session: u8,
    id: u8,
    now: u64,
    operation: DiscoveryOperation,
) -> DiscoveryRequest {
    let mut request = DiscoveryRequest {
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
    sign(key, &mut request);
    request
}

pub fn publication(
    f: &Fixture,
    member: u8,
    sequence: u64,
    id: u8,
    payload: u8,
) -> DiscoveryRequest {
    let admission = f.grant(member, &f.device);
    let authorization = f.authorize(member, &f.device);
    let ciphertext = [payload; 32];
    let mut envelope = ProfileEnvelope {
        version: 1,
        community_id: admission.community_id.clone(),
        member_id: admission.member_id.clone(),
        chat_public_key: admission.chat_public_key.clone(),
        profile_epoch: encoded(payload),
        sequence,
        issued_at: 110,
        expires_at: 400,
        nonce: BASE64URL_NOPAD.encode(&[payload; 12]),
        profile_digest: BASE64URL_NOPAD.encode(&Sha256::digest(ciphertext)),
        discriminators: BTreeMap::from([("ageBand".into(), 6)]),
        ciphertext: BASE64URL_NOPAD.encode(&ciphertext),
        signature: String::new(),
    };
    envelope.signature = BASE64URL_NOPAD.encode(
        &f.device
            .sign(&profile_signing_bytes(&envelope).unwrap())
            .to_bytes(),
    );
    operation(
        f,
        &f.device,
        member,
        11,
        id,
        110,
        DiscoveryOperation::Publish {
            publication: CachedProfile {
                admission,
                authorization,
                envelope,
            },
            lease: DiscoveryLease {
                lease_id: encoded(11),
                sequence,
                expires_at: 170,
            },
        },
    )
}

pub fn fetch(f: &Fixture, id: u8, now: u64, target: u8) -> DiscoveryRequest {
    operation(
        f,
        &f.device,
        5,
        11,
        id,
        now,
        DiscoveryOperation::Fetch {
            member_id: member_id(target),
        },
    )
}
