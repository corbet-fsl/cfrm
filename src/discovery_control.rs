//! Durable anti-abuse guards for replaceable ciphertext caches. This database
//! stores no ciphertext, decryption key, profile text, query or fetched member ID.
use crate::{
    admission::{digest, MAX_INTEGER},
    allocation::{sql_integer, stored_integer},
    discovery::{DiscoveryLimits, DiscoveryOperation, VerifiedDiscoveryRequest},
    discovery_store::{transition, MemberControl},
    Error,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::{path::Path, sync::Mutex, time::Duration};

pub struct SqliteDiscoveryControl {
    connection: Mutex<Connection>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        admission::{AdmissionGrant, DeviceAuthorization},
        discovery::{CachedProfile, DiscoveryLease, DiscriminatorDomain, ProfileEnvelope},
    };
    use std::{
        collections::BTreeMap,
        sync::{Arc, Barrier},
    };

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
            max_members: 10,
            max_devices_per_member: 4,
            max_replay_entries: 100,
            max_results: 10,
            max_scan: 10,
            publish_limit: 2,
            publish_window_seconds: 86400,
            discriminator_limit: 1,
            discriminator_window_seconds: 86400,
            read_limit: 1,
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

    fn request(operation: DiscoveryOperation, id: &str) -> VerifiedDiscoveryRequest {
        VerifiedDiscoveryRequest {
            trust_digest: "trusted-configuration".into(),
            community_id: "community.test".into(),
            member_id: "owner".into(),
            chat_public_key: "device".into(),
            session_id: "session".into(),
            request_id: id.into(),
            issued_at: 110,
            expires_at: 130,
            operation,
        }
    }

    // These are already-verified capability fixtures. Cryptographic admission
    // and ciphertext verification are exercised through the public service tests.
    fn publication(sequence: u64, ciphertext: &str) -> DiscoveryOperation {
        let admission = AdmissionGrant {
            version: 1,
            issuer_key_id: "issuer".into(),
            community_id: "community.test".into(),
            member_id: "owner".into(),
            chat_public_key: "device".into(),
            policy_digest: "policy".into(),
            issued_at: 100,
            expires_at: 900,
            signature: "admission".into(),
        };
        let authorization = DeviceAuthorization {
            version: 1,
            community_id: admission.community_id.clone(),
            member_id: admission.member_id.clone(),
            root_public_key: "root".into(),
            device_public_key: "device".into(),
            issued_at: 100,
            expires_at: 900,
            signature: "authorization".into(),
        };
        DiscoveryOperation::Publish {
            publication: CachedProfile {
                admission,
                authorization,
                envelope: ProfileEnvelope {
                    version: 1,
                    community_id: "community.test".into(),
                    member_id: "owner".into(),
                    chat_public_key: "device".into(),
                    profile_epoch: "epoch".into(),
                    sequence,
                    issued_at: 110,
                    expires_at: 400,
                    nonce: "nonce".into(),
                    profile_digest: digest(ciphertext.as_bytes()),
                    discriminators: BTreeMap::from([("ageBand".into(), 6)]),
                    ciphertext: ciphertext.into(),
                    signature: "signature".into(),
                },
            },
            lease: DiscoveryLease {
                lease_id: "session".into(),
                sequence,
                expires_at: 170,
            },
        }
    }

    #[test]
    fn durable_read_quota_survives_reopen_without_storing_targets() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("guards.sqlite");
        let control = SqliteDiscoveryControl::open(&path, Duration::from_secs(2)).unwrap();
        let first = request(
            DiscoveryOperation::Fetch {
                member_id: "PRIVATE_READ_TARGET_CANARY".into(),
            },
            "one",
        );
        control.authorize(&first, &limits(), 110).unwrap();
        drop(control);
        let control = SqliteDiscoveryControl::open(&path, Duration::from_secs(2)).unwrap();
        let second = request(
            DiscoveryOperation::Fetch {
                member_id: "OTHER_TARGET".into(),
            },
            "two",
        );
        assert!(matches!(
            control.authorize(&second, &limits(), 110),
            Err(Error::Capacity)
        ));
        let inspection = Connection::open(&path).unwrap();
        let state: String = inspection
            .query_row("SELECT state FROM cfrm_discovery_controls", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(!state.contains("PRIVATE_READ_TARGET_CANARY"));
        assert!(!state.contains("OTHER_TARGET"));
        assert!(!state.contains("request_id"));
    }

    #[test]
    fn committed_intent_recovers_ciphertext_after_cache_failure_without_redebit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("guards.sqlite");
        let control = SqliteDiscoveryControl::open(&path, Duration::from_secs(2)).unwrap();
        let first = request(publication(1, "CIPHERTEXT_CANARY"), "one");
        let commit = control.authorize(&first, &limits(), 110).unwrap();
        assert!(!commit.retry);
        assert!(matches!(
            control.with_current::<()>(&commit, |_| Err(Error::Storage)),
            Err(Error::Storage)
        ));
        drop(control);
        let control = SqliteDiscoveryControl::open(&path, Duration::from_secs(2)).unwrap();
        let retry = control.authorize(&first, &limits(), 110).unwrap();
        assert!(retry.retry);
        assert!(retry.publication.is_some());
        assert_eq!(
            control.with_current(&retry, |state| Ok(state.profile_sequence)),
            Ok(1)
        );
        let inspection = Connection::open(&path).unwrap();
        let state: String = inspection
            .query_row("SELECT state FROM cfrm_discovery_controls", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(!state.contains("CIPHERTEXT_CANARY"));
        assert!(!state.contains("ciphertext"));
    }

    #[test]
    fn newer_intent_fences_old_cache_mutation_and_historical_retry() {
        let directory = tempfile::tempdir().unwrap();
        let control = SqliteDiscoveryControl::open(
            directory.path().join("guards.sqlite"),
            Duration::from_secs(2),
        )
        .unwrap();
        let first = request(publication(1, "first"), "one");
        let stale = control.authorize(&first, &limits(), 110).unwrap();
        let current = control
            .authorize(&request(publication(2, "second"), "two"), &limits(), 110)
            .unwrap();
        assert_eq!(control.with_current(&stale, |_| Ok(())), Err(Error::Replay));
        assert_eq!(
            control.with_current(&current, |state| Ok(state.profile_sequence)),
            Ok(2)
        );
        let retry = control.authorize(&first, &limits(), 110).unwrap();
        assert!(retry.retry);
        assert!(retry.publication.is_none());
        assert_eq!(retry.control.profile_sequence, 2);
    }

    #[test]
    fn independent_connections_accept_only_one_competing_profile_revision() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("guards.sqlite");
        let a = SqliteDiscoveryControl::open(&path, Duration::from_secs(2)).unwrap();
        let b = SqliteDiscoveryControl::open(&path, Duration::from_secs(2)).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let jobs: Vec<_> = [(a, "first"), (b, "second")]
            .into_iter()
            .map(|(control, payload)| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    control
                        .authorize(&request(publication(1, payload), payload), &limits(), 110)
                        .map(|_| ())
                })
            })
            .collect();
        let results: Vec<_> = jobs.into_iter().map(|job| job.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| **r == Ok(())).count(), 1);
        assert_eq!(
            results.iter().filter(|r| **r == Err(Error::Replay)).count(),
            1
        );
    }

    #[test]
    fn persisted_scope_rejects_trust_or_quota_configuration_drift_and_clock_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let control = SqliteDiscoveryControl::open(
            directory.path().join("guards.sqlite"),
            Duration::from_secs(2),
        )
        .unwrap();
        control
            .authorize(&request(publication(1, "first"), "one"), &limits(), 110)
            .unwrap();
        let mut changed = limits();
        changed.publish_limit += 1;
        assert!(matches!(
            control.authorize(&request(publication(2, "second"), "two"), &changed, 110),
            Err(Error::PolicyMismatch)
        ));
        let mut other_trust = request(publication(2, "second"), "two");
        other_trust.trust_digest = "different-issuer".into();
        assert!(matches!(
            control.authorize(&other_trust, &limits(), 110),
            Err(Error::PolicyMismatch)
        ));
        assert!(matches!(
            control.current("community.test", "owner", 109),
            Err(Error::ClockRollback)
        ));
        assert!(control
            .current("community.test", "owner", 86511)
            .unwrap()
            .is_none());
    }

    #[test]
    fn expired_and_recreated_member_cannot_accept_an_old_cache_intent() {
        let directory = tempfile::tempdir().unwrap();
        let control = SqliteDiscoveryControl::open(
            directory.path().join("guards.sqlite"),
            Duration::from_secs(2),
        )
        .unwrap();
        let stale = control
            .authorize(&request(publication(1, "first"), "one"), &limits(), 110)
            .unwrap();
        let mut renewed = request(publication(1, "renewed"), "two");
        renewed.issued_at = 86520;
        renewed.expires_at = 86540;
        if let DiscoveryOperation::Publish { publication, lease } = &mut renewed.operation {
            publication.envelope.issued_at = 86520;
            publication.envelope.expires_at = 86800;
            lease.expires_at = 86580;
        }
        let current = control.authorize(&renewed, &limits(), 86520).unwrap();
        assert!(current.revision > stale.revision);
        assert_eq!(control.with_current(&stale, |_| Ok(())), Err(Error::Replay));
    }
}

/// A committed intent. The second transaction fences its cache mutation against
/// later intents accepted through the same shared control database.
pub(crate) struct ControlCommit {
    pub community_id: String,
    pub member_id: String,
    pub revision: u64,
    pub control: MemberControl,
    pub publication: Option<crate::discovery::CachedProfile>,
    pub retry: bool,
}

impl SqliteDiscoveryControl {
    pub fn open(path: impl AsRef<Path>, busy_timeout: Duration) -> Result<Self, Error> {
        if busy_timeout.is_zero() || busy_timeout.as_millis() > i32::MAX as u128 {
            return Err(Error::InvalidInput);
        }
        let connection = Connection::open(path).map_err(|_| Error::Storage)?;
        connection
            .busy_timeout(busy_timeout)
            .map_err(|_| Error::Storage)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS cfrm_discovery_scopes (
               community TEXT PRIMARY KEY NOT NULL,
               limits TEXT NOT NULL,
               last_now INTEGER NOT NULL,
               last_revision INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS cfrm_discovery_controls (
               community TEXT NOT NULL,
               member TEXT NOT NULL,
               revision INTEGER NOT NULL,
               expires_at INTEGER NOT NULL,
               state TEXT NOT NULL,
               PRIMARY KEY (community, member)
             );
             CREATE INDEX IF NOT EXISTS cfrm_discovery_control_expiry
               ON cfrm_discovery_controls (community, expires_at);",
            )
            .map_err(|_| Error::Storage)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub(crate) fn authorize(
        &self,
        request: &VerifiedDiscoveryRequest,
        limits: &DiscoveryLimits,
        now: u64,
    ) -> Result<ControlCommit, Error> {
        let mut connection = self.connection.lock().map_err(|_| Error::Storage)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Storage)?;
        let expected_limits = serde_json::to_string(&(&request.trust_digest, limits))
            .map_err(|_| Error::InvalidInput)?;
        let scope: Option<(String, i64, i64)> = transaction.query_row(
            "SELECT limits,last_now,last_revision FROM cfrm_discovery_scopes WHERE community=?1",
            [&request.community_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        ).optional().map_err(|_| Error::Storage)?;
        let previous_revision = scope
            .as_ref()
            .map(|scope| stored_integer(scope.2))
            .transpose()?
            .unwrap_or(0);
        if let Some((stored_limits, last_now, _)) = scope {
            if stored_limits != expected_limits {
                return Err(Error::PolicyMismatch);
            }
            if now < stored_integer(last_now)? {
                return Err(Error::ClockRollback);
            }
        }
        // Scope-wide generations survive member-row expiry, avoiding ABA when
        // a delayed cache intent outlives and then meets a recreated row.
        let revision = previous_revision
            .checked_add(1)
            .filter(|n| *n <= MAX_INTEGER)
            .ok_or(Error::Capacity)?;
        transaction.execute(
            "INSERT INTO cfrm_discovery_scopes(community,limits,last_now,last_revision) VALUES(?1,?2,?3,?4)
             ON CONFLICT(community) DO UPDATE SET last_now=excluded.last_now,last_revision=excluded.last_revision",
            params![request.community_id, expected_limits, sql_integer(now)?, sql_integer(revision)?]
        ).map_err(|_| Error::Storage)?;
        transaction
            .execute(
                "DELETE FROM cfrm_discovery_controls WHERE community=?1 AND expires_at<=?2",
                params![request.community_id, sql_integer(now)?],
            )
            .map_err(|_| Error::Storage)?;
        let previous: Option<String> = transaction
            .query_row(
                "SELECT state FROM cfrm_discovery_controls WHERE community=?1 AND member=?2",
                params![request.community_id, request.member_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| Error::Storage)?;
        if previous.is_none() {
            let count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM cfrm_discovery_controls WHERE community=?1",
                    [&request.community_id],
                    |row| row.get(0),
                )
                .map_err(|_| Error::Storage)?;
            if stored_integer(count)? >= limits.max_members as u64 {
                return Err(Error::Capacity);
            }
        }
        let state = match previous {
            Some(state) => serde_json::from_str(&state).map_err(|_| Error::Storage)?,
            None => MemberControl::default(),
        };
        let mut change = transition(state, request, limits, now)?;
        // A retry can recover a blob lost after the durable intent committed,
        // but an old successful publication cannot replace a newer revision.
        if change.retry {
            if let DiscoveryOperation::Publish { publication, .. } = &request.operation {
                let hash =
                    digest(&serde_json::to_vec(publication).map_err(|_| Error::InvalidInput)?);
                if hash == change.control.publication_hash {
                    change.publication = Some(publication.clone());
                }
            }
        }
        let encoded = serde_json::to_string(&change.control).map_err(|_| Error::Storage)?;
        transaction
            .execute(
                "INSERT INTO cfrm_discovery_controls(community,member,revision,expires_at,state)
               VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(community,member) DO UPDATE SET
               revision=excluded.revision,expires_at=excluded.expires_at,state=excluded.state",
                params![
                    request.community_id,
                    request.member_id,
                    sql_integer(revision)?,
                    sql_integer(change.control.retain_until)?,
                    encoded
                ],
            )
            .map_err(|_| Error::Storage)?;
        transaction.commit().map_err(|_| Error::Storage)?;
        Ok(ControlCommit {
            community_id: request.community_id.clone(),
            member_id: request.member_id.clone(),
            revision,
            control: change.control,
            publication: change.publication,
            retry: change.retry,
        })
    }

    /// Keep the durable writer fence held until the bounded cache mutation
    /// finishes. A closure must not call back into this authority recursively.
    pub(crate) fn with_current<T>(
        &self,
        commit: &ControlCommit,
        apply: impl FnOnce(&MemberControl) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut connection = self.connection.lock().map_err(|_| Error::Storage)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Storage)?;
        let current: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM cfrm_discovery_controls WHERE community=?1 AND member=?2",
                params![commit.community_id, commit.member_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| Error::Storage)?;
        if current.map(stored_integer).transpose()? != Some(commit.revision) {
            return Err(Error::Replay);
        }
        let result = apply(&commit.control)?;
        transaction.commit().map_err(|_| Error::Storage)?;
        Ok(result)
    }

    /// Read only current bounded authority. This records neither the target nor
    /// an association with the requesting reader; expired rows are invisible.
    pub(crate) fn current(
        &self,
        community_id: &str,
        member_id: &str,
        now: u64,
    ) -> Result<Option<MemberControl>, Error> {
        let mut connection = self.connection.lock().map_err(|_| Error::Storage)?;
        let transaction = connection.transaction().map_err(|_| Error::Storage)?;
        let last_now: Option<i64> = transaction
            .query_row(
                "SELECT last_now FROM cfrm_discovery_scopes WHERE community=?1",
                [community_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| Error::Storage)?;
        if last_now
            .map(stored_integer)
            .transpose()?
            .is_some_and(|last| now < last)
        {
            return Err(Error::ClockRollback);
        }
        let state: Option<String> = transaction.query_row(
            "SELECT state FROM cfrm_discovery_controls WHERE community=?1 AND member=?2 AND expires_at>?3",
            params![community_id, member_id, sql_integer(now)?], |row| row.get(0)
        ).optional().map_err(|_| Error::Storage)?;
        state
            .map(|value| serde_json::from_str(&value).map_err(|_| Error::Storage))
            .transpose()
    }
}
