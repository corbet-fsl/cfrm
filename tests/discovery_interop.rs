use cfrm::{
    admission::AdmissionTrust,
    discovery::{
        profile_aad_bytes, profile_signing_bytes, request_signing_bytes, verify_cached_profile,
        CachedProfile, DiscoveryLimits, DiscoveryRequest, DiscoveryResponse, DiscoveryService,
        DiscriminatorDomain,
    },
    discovery_store::MemoryDiscoveryStore,
};
use data_encoding::BASE64URL_NOPAD;
use serde_json::Value;
use std::{collections::BTreeMap, process::Command};

fn limits() -> DiscoveryLimits {
    DiscoveryLimits {
        max_request_bytes: 16384,
        max_record_bytes: 8192,
        max_response_bytes: 32768,
        max_ciphertext_bytes: 4096,
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
                "region".into(),
                DiscriminatorDomain::Enum {
                    values: vec![0, 1, 2],
                },
            ),
        ]),
    }
}

#[test]
fn real_webcrypto_publication_and_requests_are_accepted_by_rust() {
    let output = Command::new("node")
        .arg(format!(
            "{}/test/profile-discovery-interop.mjs",
            env!("CARGO_MANIFEST_DIR")
        ))
        .output()
        .expect("Node is required for the browser/native profile wire contract");
    assert!(
        output.status.success(),
        "WebCrypto fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fixture: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(fixture["fixtureOnly"], true);
    let trust = AdmissionTrust {
        community_id: fixture["trust"]["communityId"].as_str().unwrap().into(),
        policy_digest: fixture["trust"]["policyDigest"].as_str().unwrap().into(),
        issuer_public_key: BASE64URL_NOPAD
            .decode(
                fixture["trust"]["issuerPublicKey"]
                    .as_str()
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let publication: CachedProfile =
        serde_json::from_value(fixture["publication"].clone()).unwrap();
    let requests: Vec<DiscoveryRequest> =
        serde_json::from_value(fixture["requests"].clone()).unwrap();
    let now = fixture["now"].as_u64().unwrap();
    verify_cached_profile(&publication, &trust, &limits(), now).unwrap();
    assert_eq!(
        BASE64URL_NOPAD.encode(&profile_signing_bytes(&publication.envelope).unwrap()),
        fixture["profileSigningBytes"].as_str().unwrap()
    );
    assert_eq!(
        BASE64URL_NOPAD.encode(&profile_aad_bytes(&publication.envelope).unwrap()),
        fixture["profileAssociatedData"].as_str().unwrap()
    );
    for (index, request) in requests.iter().enumerate() {
        assert_eq!(
            BASE64URL_NOPAD.encode(&request_signing_bytes(request).unwrap()),
            fixture["requestSigningBytes"][index].as_str().unwrap()
        );
    }
    let service =
        DiscoveryService::new(trust.clone(), limits(), MemoryDiscoveryStore::new()).unwrap();
    assert_eq!(
        service.execute(&requests[0], now),
        Ok(DiscoveryResponse::Updated)
    );
    assert_eq!(
        service.execute(&requests[1], now),
        Ok(DiscoveryResponse::Profile {
            publication: Some(publication.clone())
        })
    );

    let recovery: Vec<DiscoveryRequest> =
        serde_json::from_value(fixture["recoveryRequests"].clone()).unwrap();
    assert_eq!(
        recovery[0], recovery[1],
        "uncertain cache retry must preserve the full signed request"
    );
    let mut limited = limits();
    limited.publish_limit = 1;
    let recovery_service =
        DiscoveryService::new(trust.clone(), limited, MemoryDiscoveryStore::new()).unwrap();
    assert_eq!(
        recovery_service.execute(&recovery[0], now),
        Ok(DiscoveryResponse::Updated)
    );
    assert_eq!(
        recovery_service.execute(&recovery[1], now),
        Ok(DiscoveryResponse::Updated)
    );
    assert_eq!(
        recovery_service.execute(&recovery[2], now + 11),
        Ok(DiscoveryResponse::Updated),
        "fresh wrapper repairs the same publication without another quota debit"
    );

    let mut altered = publication.clone();
    altered.envelope.discriminators.insert("ageBand".into(), 7);
    assert!(verify_cached_profile(&altered, &trust, &limits(), now).is_err());
    let mut altered = publication.clone();
    altered.envelope.profile_epoch = BASE64URL_NOPAD.encode(&[99; 32]);
    assert!(verify_cached_profile(&altered, &trust, &limits(), now).is_err());
    let mut altered = requests[1].clone();
    altered.request_id = BASE64URL_NOPAD.encode(&[98; 32]);
    assert!(service.execute(&altered, now).is_err());
}
