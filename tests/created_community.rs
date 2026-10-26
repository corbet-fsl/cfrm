//! A forum follows a community that cvld created: the community is signed under
//! its address (the genesis scope), while the registry's `id` only names storage,
//! throttle and state. The trust feed installs only when the genesis names exactly
//! the community the registry record carries.
mod support;

use cfrm::tenant::{Record, State};
use serde_json::json;
use support::{feed, issuer};

const NOW: u64 = 1_800_000_000;
const ID: &str = "0123456789abcdef0123456789abcdef";

fn config() -> csrn::feed::Config {
    csrn::feed::Config {
        retry_entropy: 15,
        refresh_seconds: 30,
        poll_seconds: 1,
        request_seconds: 30,
        initial_backoff_seconds: 1,
        maximum_backoff_seconds: 10,
        maximum_staleness_seconds: 60,
    }
}

/// The record the registry serves for the support issuer's community ("garden"),
/// anchored on the fingerprint of its genesis; the registry id is unrelated.
fn record(community: &str) -> (Record, Vec<u8>) {
    let genesis = issuer(NOW).genesis().unwrap();
    let fingerprint = csgn::verify_genesis(&genesis).unwrap().fingerprint();
    let record = Record {
        id: ID.into(),
        community: community.into(),
        state: State::Live,
        origins: vec!["https://garden.example.test".into()],
        trust_origin: "https://api.garden.example.test".into(),
        fingerprint: fingerprint.iter().map(|b| format!("{b:02x}")).collect(),
    };
    let mut full = feed(NOW, 1, json!({"members":[],"devices":[]}));
    full["genesis"] = json!(genesis);
    (record, serde_json::to_vec(&full).unwrap())
}

fn install(record: &Record, bytes: &[u8]) -> csrn::Result<String> {
    let mut assurance = record.assurance(config()).unwrap();
    let fetch = assurance.start(NOW).unwrap();
    assurance.on_feed(fetch.id(), bytes, NOW)?;
    Ok(assurance.current(NOW)?.community().to_owned())
}

#[test]
fn a_forum_follows_a_created_community_under_its_signing_name() {
    let (record, bytes) = record("garden");
    assert_ne!(record.id, record.community);
    assert_eq!(install(&record, &bytes).unwrap(), "garden");
}

#[test]
fn a_name_the_genesis_does_not_sign_is_refused() {
    // The registry cannot choose a name the genesis does not carry: neither a
    // different label nor the storage id (the former leftover bug).
    for name in ["gardenclub", ID, "garde"] {
        let (record, bytes) = record(name);
        let error = install(&record, &bytes).unwrap_err();
        assert!(
            matches!(error, csrn::Error::Trust(cchr::Error::Unauthenticated)),
            "{name}: {error:?}"
        );
    }
}
