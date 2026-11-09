//! Real partial owner round trips, below the Forum admission boundary.
//! These exercise person/profile/device authority, not mandatory G2 currentness.
#![cfg(all(feature = "server", not(target_arch = "wasm32")))]

use crate::support::*;
use cgth::{Gather, clkp, cmbl, cmmr, cswb, cthl};
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

#[derive(Clone)]
struct Time(Arc<AtomicU64>);
impl Time {
    fn new() -> Self {
        Self(Arc::new(AtomicU64::new(2_000_000_000_000)))
    }
    fn advance(&self, milliseconds: u64) {
        self.0.fetch_add(milliseconds, Ordering::SeqCst);
    }
}
impl Clock for Time {
    fn now(&self) -> Result<u64, cmmr::Error> {
        Ok(self.0.load(Ordering::SeqCst))
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

type Owners = Gather<cvtl::Volatile<Time>, Time, Random, cthl::MemoryStore>;
struct ForumOwners {
    assurance: csrn::Assurance,
    gather: Owners,
    storage: cvtl::Volatile<Time>,
    clock: Time,
}
fn verification(charter: &cchr::VerifiedCharter) -> cswb::Verification<'_> {
    cswb::Verification {
        charter,
        action: ACTION,
    }
}
impl ForumOwners {
    fn new(clock: &Time) -> Self {
        let now = clock.now().unwrap() / 1000;
        let assurance = csrn::Assurance::new(
            cchr::Configuration {
                origin: "https://identity.example.test".into(),
                community: "garden".into(),
                key_ring: issuer(now).key_ring().to_cbor(),
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
                maximum_staleness_seconds: 120,
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
        let presence = cswb::Switchboard::new(
            storage.clone(),
            clock.clone(),
            Random,
            "garden".into(),
            cswb::Limits {
                lease_ms: 60000,
                publication_bytes: cpfl::MAX_PROFILE_BYTES,
                ciphertext_bytes: cpfl::MAX_PROFILE_BYTES,
            },
        )
        .unwrap();
        let lookup = clkp::Lookup::new(
            storage.clone(),
            Random,
            clkp::LookupLimits {
                candidates: 3,
                publication_bytes: cpfl::MAX_PROFILE_BYTES * 3,
            },
        )
        .unwrap();
        let rooms = cmbl::Assembly::new(
            storage.clone(),
            "garden".into(),
            "boot".into(),
            cmbl::Limits {
                connections: 8,
                relay_messages: 8,
                message_bytes: 1024,
                lifetime_ms: 10000,
                proof_bytes: cmbl::passes::MAX_PROOF_BYTES,
                operation_receipts: 16,
            },
        )
        .unwrap();
        let throttle = cthl::Throttle::new(
            "garden",
            cfrm::actions().into_iter().map(|action| {
                (
                    action.name,
                    cthl::Limit::new(100, Duration::from_secs(1)).unwrap(),
                )
            }),
            cthl::MemoryStore::new(NonZeroUsize::new(32).unwrap()),
        )
        .unwrap();
        Self {
            assurance,
            gather: Gather::new(presence, throttle, rooms, lookup),
            storage,
            clock: clock.clone(),
        }
    }
    fn bootstrap(&mut self) {
        let now = self.clock.now().unwrap() / 1000;
        let fetch = self.assurance.start(now).unwrap();
        self.assurance
            .on_feed(
                fetch.id(),
                &serde_json::to_vec(&feed(
                    now,
                    1,
                    serde_json::json!({"members":[],"devices":[]}),
                ))
                .unwrap(),
                now,
            )
            .unwrap();
    }
    fn announce_revision(&mut self) {
        self.clock.advance(1000);
        let now = self.clock.now().unwrap() / 1000;
        let poll = self.assurance.next(now).unwrap().unwrap();
        assert!(matches!(
            poll.action(),
            csrn::feed::Action::Poll { revision: 1 }
        ));
        self.assurance
            .on_announcement(
                poll.id(),
                &serde_json::to_vec(&serde_json::json!({
                    "revision":2,"policy_epoch":2,"changed":true,
                }))
                .unwrap(),
                now,
            )
            .unwrap();
    }
    fn install_revision(&mut self, issued_at: u64, revoked: serde_json::Value) {
        let now = self.clock.now().unwrap() / 1000;
        let fetch = self.assurance.next(now).unwrap().unwrap();
        assert!(matches!(fetch.action(), csrn::feed::Action::Fetch));
        self.assurance
            .on_feed(
                fetch.id(),
                &serde_json::to_vec(&feed(issued_at, 2, revoked)).unwrap(),
                now,
            )
            .unwrap();
    }
    async fn challenge(&mut self, fixture: &Fixture) -> cswb::Challenge {
        let charter = self
            .assurance
            .current(self.clock.now().unwrap() / 1000)
            .unwrap();
        self.gather
            .challenge(ORIGIN, &fixture.publication, &verification(charter), &clean)
            .await
            .unwrap()
    }
    async fn admit(
        &mut self,
        fixture: &Fixture,
        challenge: &cswb::Challenge,
    ) -> Result<(cswb::Session, cswb::Live), cgth::Error> {
        let signature = fixture
            .device
            .sign(&cswb::challenge_message(
                ORIGIN,
                "garden",
                challenge,
                &fixture.publication.signed,
            ))
            .to_bytes();
        let charter = self
            .assurance
            .current(self.clock.now().unwrap() / 1000)
            .unwrap();
        self.gather
            .admit(
                cswb::EntryProof {
                    origin: ORIGIN,
                    challenge,
                    signature: &signature,
                    publication: &fixture.publication,
                },
                &verification(charter),
                &clean,
            )
            .await
    }
    async fn enter(&mut self, fixture: &Fixture) -> (cswb::Session, cswb::Live) {
        let challenge = self.challenge(fixture).await;
        self.admit(fixture, &challenge).await.unwrap()
    }
    async fn authorize(
        &mut self,
        session: &cswb::Session,
        fixture: &Fixture,
        nonce: u8,
        action: &str,
    ) -> Result<cswb::Current, cgth::Error> {
        // Trusted owner-port inputs; this is not a Forum action dispatcher.
        let body = b"direct-owner-scenario";
        let possession = cswb::Possession {
            nonce: [nonce; 16],
            signature: fixture
                .device
                .sign(&cswb::request_message(
                    ORIGIN,
                    action,
                    session,
                    &[nonce; 16],
                    body,
                ))
                .to_bytes()
                .to_vec(),
        };
        let charter = self
            .assurance
            .current(self.clock.now().unwrap() / 1000)
            .unwrap();
        self.gather
            .authorize(
                cswb::RequestProof {
                    origin: ORIGIN,
                    session,
                    action,
                    body,
                    possession: &possession,
                },
                &verification(charter),
                &clean,
            )
            .await
    }
    async fn page(
        &mut self,
        session: &cswb::Session,
        fixture: &Fixture,
        nonce: u8,
    ) -> Result<clkp::Matches, cgth::Error> {
        let current = self.authorize(session, fixture, nonce, "search").await?;
        let charter = self
            .assurance
            .current(self.clock.now().unwrap() / 1000)
            .unwrap();
        self.gather
            .page(
                clkp::PageRequest {
                    session,
                    current: &current,
                    cursor: None,
                    limit: 3,
                },
                &verification(charter),
                &clean,
            )
            .await
    }
    async fn room(
        &self,
        command: &cmbl::Request,
        proof: &[u8],
    ) -> Result<cmbl::Outcome, cgth::Error> {
        let now = self.clock.now().unwrap();
        let epoch = self.gather.room_epoch(now).await?.clone();
        let verifier =
            cmbl::passes::Verifier::new(epoch, "boot".into()).map_err(cgth::Error::Rooms)?;
        self.gather.room(command, proof, &verifier, now).await
    }
}

#[tokio::test]
async fn signed_member_revocation_removes_a_candidate_and_refuses_its_session() {
    let clock = Time::new();
    let now = clock.now().unwrap() / 1000;
    let mut owners = ForumOwners::new(&clock);
    owners.bootstrap();
    let alice = Fixture::new("alice", 1, now).await;
    let bob = Fixture::new("bob", 1, now).await;
    let (a, _) = owners.enter(&alice).await;
    let (b, _) = owners.enter(&bob).await;
    assert_eq!(
        owners.page(&b, &bob, 1).await.unwrap().entries[0].member,
        "alice"
    );
    owners.announce_revision();
    // An unsigned announcement closes readiness without replacing trust.
    assert!(
        owners
            .assurance
            .current(clock.now().unwrap() / 1000)
            .is_err()
    );
    owners.install_revision(now, serde_json::json!({"members":["alice"],"devices":[]}));
    assert!(owners.page(&b, &bob, 3).await.unwrap().entries.is_empty());
    assert!(
        owners
            .storage
            .get(&cswb::attendance_key(
                "alice",
                &alice.device.verifying_key().to_bytes()
            ))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        owners
            .storage
            .get(&cswb::attendance_key(
                "bob",
                &bob.device.verifying_key().to_bytes()
            ))
            .await
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        owners.page(&a, &alice, 1).await,
        Err(cgth::Error::Presence(cswb::Error::Absent))
    ));
    let charter = owners
        .assurance
        .current(clock.now().unwrap() / 1000)
        .unwrap();
    assert!(matches!(
        owners
            .gather
            .challenge(ORIGIN, &alice.publication, &verification(charter), &clean)
            .await,
        Err(cgth::Error::Presence(cswb::Error::TrustUnavailable))
    ));
    owners.storage.close();
    assert_eq!(owners.storage.state(), cmmr::State::Closed);
}

#[tokio::test]
async fn signed_device_revocation_refuses_the_next_request_and_preserves_other_devices() {
    let clock = Time::new();
    let now = clock.now().unwrap() / 1000;
    let mut owners = ForumOwners::new(&clock);
    owners.bootstrap();
    let alice = Fixture::new("alice", 1, now).await;
    let bob = Fixture::with_device("bob", 1, now, 14).await;
    let (a, _) = owners.enter(&alice).await;
    let (b, _) = owners.enter(&bob).await;
    owners.announce_revision();
    owners.install_revision(
        now,
        serde_json::json!({"members":[],
        "devices":[alice.device.verifying_key().to_bytes()]}),
    );
    assert!(matches!(
        owners.page(&a, &alice, 1).await,
        Err(cgth::Error::Presence(cswb::Error::TrustUnavailable))
    ));
    assert!(
        owners
            .storage
            .get(&cswb::attendance_key(
                "alice",
                &alice.device.verifying_key().to_bytes()
            ))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        owners
            .storage
            .get(&cswb::attendance_key(
                "bob",
                &bob.device.verifying_key().to_bytes()
            ))
            .await
            .unwrap()
            .is_some()
    );
    assert!(owners.page(&b, &bob, 1).await.unwrap().entries.is_empty());
    owners.storage.close();
    assert_eq!(owners.storage.state(), cmmr::State::Closed);
}

#[tokio::test]
async fn a_new_attendance_fences_old_departures_and_heartbeats() {
    let clock = Time::new();
    let now = clock.now().unwrap() / 1000;
    let mut owners = ForumOwners::new(&clock);
    owners.bootstrap();
    let alice = Fixture::new("alice", 1, now).await;
    let (old, old_live) = owners.enter(&alice).await;
    let (current, _) = owners.enter(&alice).await;
    assert!(old != current);
    let replacement = owners
        .storage
        .get(&cswb::attendance_key(
            "alice",
            &alice.device.verifying_key().to_bytes(),
        ))
        .await
        .unwrap()
        .unwrap();
    for (nonce, action) in [(1, "depart"), (2, "heartbeat")] {
        assert!(matches!(
            owners.authorize(&old, &alice, nonce, action).await,
            Err(cgth::Error::Presence(cswb::Error::Stale))
        ));
        let retained = owners
            .storage
            .get(&cswb::attendance_key(
                "alice",
                &alice.device.verifying_key().to_bytes(),
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.generation, replacement.generation);
        assert_eq!(retained.revision, replacement.revision);
    }
    // Departure itself is generation-fenced even without the dispatcher.
    assert_eq!(owners.gather.depart(&old).await.unwrap(), 0);
    assert_eq!(
        owners
            .storage
            .get(&cswb::attendance_key(
                "alice",
                &alice.device.verifying_key().to_bytes()
            ))
            .await
            .unwrap()
            .unwrap()
            .revision,
        replacement.revision
    );
    assert_ne!(old_live.revision, replacement.revision);
    owners.page(&current, &alice, 1).await.unwrap();
    owners
        .authorize(&current, &alice, 2, "depart")
        .await
        .unwrap();
    owners.gather.depart(&current).await.unwrap();
    assert!(
        owners
            .storage
            .get(&cswb::attendance_key(
                "alice",
                &alice.device.verifying_key().to_bytes()
            ))
            .await
            .unwrap()
            .is_none()
    );
    owners.storage.close();
    assert_eq!(owners.storage.state(), cmmr::State::Closed);
}

#[tokio::test]
async fn the_exclusive_presence_deadline_requires_a_new_attendance() {
    let clock = Time::new();
    let now = clock.now().unwrap() / 1000;
    let mut owners = ForumOwners::new(&clock);
    owners.bootstrap();
    let alice = Fixture::new("alice", 1, now).await;
    let (old, old_live) = owners.enter(&alice).await;
    clock.advance(old_live.deadline - clock.now().unwrap() - 1);
    owners.page(&old, &alice, 1).await.unwrap();
    clock.advance(1);
    assert!(matches!(
        owners.authorize(&old, &alice, 2, "heartbeat").await,
        Err(cgth::Error::Presence(cswb::Error::Absent))
    ));
    assert!(
        owners
            .storage
            .get(&cswb::attendance_key(
                "alice",
                &alice.device.verifying_key().to_bytes()
            ))
            .await
            .unwrap()
            .is_none()
    );
    let (current, live) = owners.enter(&alice).await;
    assert!(old != current);
    assert_eq!(live.deadline, clock.now().unwrap() + crbk::FORUM_LEASE_MS);
    owners.page(&current, &alice, 1).await.unwrap();
    owners.storage.close();
    assert_eq!(owners.storage.state(), cmmr::State::Closed);
}

#[tokio::test]
async fn real_owner_admission_match_rooms_and_heartbeat() {
    let clock = Time::new();
    let now = clock.now().unwrap() / 1000;
    let mut owners = ForumOwners::new(&clock);
    owners.bootstrap();
    let alice = Fixture::new("alice", 1, now).await;
    let bob = Fixture::new("bob", 1, now).await;
    let challenge = owners.challenge(&alice).await;
    let (a, a_live) = owners.admit(&alice, &challenge).await.unwrap();
    // The consumed challenge is refused as stale against the live entry.
    assert!(matches!(
        owners.admit(&alice, &challenge).await,
        Err(cgth::Error::Presence(cswb::Error::Stale))
    ));
    owners.enter(&bob).await;
    let page = owners.page(&a, &alice, 1).await.unwrap();
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].member, "bob");
    assert_eq!(page.entries[0].publication, bob.publication.signed);
    assert!(matches!(
        owners.page(&a, &alice, 1).await,
        Err(cgth::Error::Presence(cswb::Error::Storage(
            cmmr::Error::Conflict
        )))
    ));
    let current = owners.authorize(&a, &alice, 2, "ciphertext").await.unwrap();
    let charter = owners.assurance.current(now).unwrap();
    let ciphertext = owners
        .gather
        .ciphertext(
            clkp::PageRequest {
                session: &a,
                current: &current,
                cursor: None,
                limit: 1,
            },
            ("bob", 1),
            &verification(charter),
            &clean,
        )
        .await
        .unwrap();
    assert_eq!(ciphertext, bob.publication.ciphertext);

    // Original signed quota and current sealed owner capability, no room identity
    // in issuance. No complete Forum/G2 admission is claimed by this partial test.
    crbk::ForumSettings::from_snapshot(charter.settings(now).unwrap()).unwrap();
    // A small budget of this test's own, so the Capacity refusal is reachable without issuing
    // the production quota (a code constant) many times over.
    let quota: u16 = 4;
    let issuer = cmbl::passes::issuer::BudgetedIssuer::create(
        owners.storage.clone(),
        "garden".into(),
        1,
        now * 1000,
        (now + 60) * 1000,
        quota,
    )
    .await
    .unwrap();
    owners.gather.install_room_issuer(issuer).unwrap();
    let current = owners
        .authorize(&a, &alice, 20, "room_epoch")
        .await
        .unwrap();
    owners.gather.read(&a, &current).await.unwrap();
    let epoch = owners.gather.room_epoch(now * 1000).await.unwrap().clone();
    let room = [41; 16];
    let prepared = cmbl::passes::PreparedPass::new(&epoch, room, now * 1000).unwrap();
    let first_current = owners
        .authorize(&a, &alice, 21, "room_issue")
        .await
        .unwrap();
    let first = owners
        .gather
        .issue_room_pass(&first_current, [1; 16], &prepared.request(), now * 1000)
        .await
        .unwrap();
    let retry_current = owners
        .authorize(&a, &alice, 22, "room_issue")
        .await
        .unwrap();
    let retry = owners
        .gather
        .issue_room_pass(&retry_current, [1; 16], &prepared.request(), now * 1000)
        .await
        .unwrap();
    assert_eq!(first, retry);
    for operation in 2..=4 {
        let current = owners
            .authorize(&a, &alice, 22 + operation, "room_issue")
            .await
            .unwrap();
        owners
            .gather
            .issue_room_pass(&current, [operation; 16], &prepared.request(), now * 1000)
            .await
            .unwrap();
    }
    let current = owners
        .authorize(&a, &alice, 27, "room_issue")
        .await
        .unwrap();
    assert_eq!(
        owners
            .gather
            .issue_room_pass(&current, [5; 16], &prepared.request(), now * 1000)
            .await,
        Err(cgth::Error::Rooms(cmbl::Error::Capacity))
    );
    let pass = prepared.finalize(&first, now * 1000).unwrap();
    let resumed = cmbl::Request {
        room,
        operation: [51; 16],
        action: cmbl::Action::Resume {
            connection: pass.connection(),
        },
    };
    let resumed = owners
        .room(&resumed, &pass.prove(&resumed, "boot", now * 1000).unwrap())
        .await
        .unwrap();
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
    let proof = pass.prove(&ordered, "boot", now * 1000).unwrap();
    let outcome = owners.room(&ordered, &proof).await.unwrap();
    assert_eq!(outcome.counter, 1);
    assert_eq!(outcome.ordering, resumed.ordering);
    assert_eq!(owners.room(&ordered, &proof).await.unwrap(), outcome);
    let read = cmbl::Request {
        room,
        operation: [53; 16],
        action: cmbl::Action::Read { after: 0 },
    };
    let proof = pass.prove(&read, "boot", now * 1000).unwrap();
    let result = owners.room(&read, &proof).await.unwrap();
    assert_eq!(result.frames[0].ciphertext, [9, 8, 7]);
    let anchor = owners
        .storage
        .get("room-pass-issuer")
        .await
        .unwrap()
        .unwrap();
    owners
        .storage
        .delete_generation(&anchor.generation)
        .await
        .unwrap();
    assert_eq!(
        owners.room(&read, &proof).await,
        Err(cgth::Error::Rooms(cmbl::Error::Storage))
    );
    assert!(matches!(
        owners.gather.room_epoch(now * 1000).await,
        Err(cgth::Error::Rooms(cmbl::Error::Storage))
    ));

    // The original owner heartbeat commits a fresh revision. Controller queue
    // cancellation remains a runtime refusal test while G2 is unavailable.
    let current = owners.authorize(&a, &alice, 3, "heartbeat").await.unwrap();
    let live = owners
        .gather
        .heartbeat(&a, &current, a_live.revision)
        .await
        .unwrap();
    let committed = owners
        .storage
        .get(&cswb::attendance_key(
            "alice",
            &alice.device.verifying_key().to_bytes(),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(committed.revision, live.revision);
    assert_ne!(committed.revision, a_live.revision);
    owners.storage.close();
    assert_eq!(owners.storage.state(), cmmr::State::Closed);
}

#[tokio::test]
async fn two_devices_of_one_member_hold_sessions_at_the_same_time() {
    let clock = Time::new();
    let now = clock.now().unwrap() / 1000;
    let mut owners = ForumOwners::new(&clock);
    owners.bootstrap();
    let alice_one = Fixture::new("alice", 1, now).await;
    let alice_two = Fixture::with_device("alice", 1, now, 14).await;
    let bob_one = Fixture::new("bob", 1, now).await;
    let (a1, a1_live) = owners.enter(&alice_one).await;
    let (a2, a2_live) = owners.enter(&alice_two).await;
    // Both device sessions stay live: neither heartbeat is stale.
    let mut a2_revision = a2_live.revision;
    for (session, live, fixture, nonce) in [
        (&a1, &a1_live, &alice_one, 1),
        (&a2, &a2_live, &alice_two, 2),
    ] {
        let current = owners
            .authorize(session, fixture, nonce, "heartbeat")
            .await
            .unwrap();
        let renewed = owners
            .gather
            .heartbeat(session, &current, live.revision)
            .await
            .unwrap();
        if session == &a2 {
            a2_revision = renewed.revision;
        }
    }
    // One member counts once: a search from bob sees alice exactly once.
    let (b1, _) = owners.enter(&bob_one).await;
    let members: Vec<String> = owners
        .page(&b1, &bob_one, 3)
        .await
        .unwrap()
        .entries
        .into_iter()
        .map(|entry| entry.member)
        .collect();
    assert_eq!(members, vec!["alice"]);
    // Disconnecting one device keeps the member present on the other.
    owners.gather.depart(&a1).await.unwrap();
    let current = owners
        .authorize(&a2, &alice_two, 4, "heartbeat")
        .await
        .unwrap();
    owners
        .gather
        .heartbeat(&a2, &current, a2_revision)
        .await
        .unwrap();
    let members: Vec<String> = owners
        .page(&b1, &bob_one, 5)
        .await
        .unwrap()
        .entries
        .into_iter()
        .map(|entry| entry.member)
        .collect();
    assert_eq!(members, vec!["alice"]);
    // Two members with two devices each count two members, never four
    // devices: each side sees exactly the other member once.
    let bob_two = Fixture::with_device("bob", 1, now, 15).await;
    let (_b2, _) = owners.enter(&bob_two).await;
    let members: Vec<String> = owners
        .page(&a2, &alice_two, 6)
        .await
        .unwrap()
        .entries
        .into_iter()
        .map(|entry| entry.member)
        .collect();
    assert_eq!(members, vec!["bob"]);
    let members: Vec<String> = owners
        .page(&_b2, &bob_two, 7)
        .await
        .unwrap()
        .entries
        .into_iter()
        .map(|entry| entry.member)
        .collect();
    assert_eq!(members, vec!["alice"]);
    owners.storage.close();
    assert_eq!(owners.storage.state(), cmmr::State::Closed);
}
