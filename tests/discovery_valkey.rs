#![cfg(feature = "discovery-valkey")]
mod common;
#[path = "common/discovery.rs"]
mod fixtures;
// The shared fixture's parent is this module, matching common's fixture names.
use cfrm::{
    discovery::*,
    discovery_control::SqliteDiscoveryControl,
    discovery_valkey::{ValkeyConfig, ValkeyDiscoveryStore},
    Error,
};
use common::{encoded, member_id, Fixture};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    sync::{Arc, Barrier},
    time::{Duration, Instant},
};

struct OwnedServer {
    child: Child,
    directory: tempfile::TempDir,
    url: String,
}

impl OwnedServer {
    fn start() -> Option<Self> {
        let executable = ["valkey-server", "redis-server"]
            .into_iter()
            .find(|binary| {
                Command::new(binary)
                    .arg("--version")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|status| status.success())
            });
        let Some(executable) = executable else {
            if std::env::var_os("CFRM_REQUIRE_VALKEY").is_some() {
                panic!("CFRM_REQUIRE_VALKEY is set but no preinstalled valkey-server/redis-server exists");
            }
            eprintln!("SKIP actual Valkey integration: neither valkey-server nor redis-server is installed");
            return None;
        };
        let directory = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let child = Command::new(executable)
            .args([
                "--bind",
                "127.0.0.1",
                "--protected-mode",
                "yes",
                "--port",
                &port.to_string(),
                "--save",
                "",
                "--appendonly",
                "no",
                "--maxmemory",
                "16mb",
                "--maxmemory-policy",
                "noeviction",
            ])
            .arg("--dir")
            .arg(directory.path())
            .arg("--logfile")
            .arg(directory.path().join("server.log"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut owned = Self {
            child,
            directory,
            url: format!("redis://127.0.0.1:{port}/"),
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                owned.child.try_wait().unwrap().is_none(),
                "owned cache exited before readiness"
            );
            if let Ok(mut connection) = redis::Client::open(owned.url.as_str())
                .unwrap()
                .get_connection_with_timeout(Duration::from_millis(100))
            {
                connection
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                if let Ok(info) = redis::cmd("INFO")
                    .arg("server")
                    .query::<String>(&mut connection)
                {
                    let actual = info
                        .lines()
                        .find_map(|line| line.strip_prefix("process_id:"))
                        .map(str::trim);
                    assert_eq!(
                        actual,
                        Some(owned.child.id().to_string().as_str()),
                        "loopback endpoint is not the owned child"
                    );
                    break;
                }
            }
            assert!(
                Instant::now() < deadline,
                "owned cache did not become ready"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Some(owned)
    }

    fn store(&self, namespace: &str, database: &Path) -> ValkeyDiscoveryStore {
        let control =
            Arc::new(SqliteDiscoveryControl::open(database, Duration::from_secs(5)).unwrap());
        ValkeyDiscoveryStore::connect(
            ValkeyConfig {
                url: self.url.clone(),
                namespace: namespace.into(),
                pool_size: 4,
                connect_timeout: Duration::from_secs(2),
                io_timeout: Duration::from_secs(2),
                pool_timeout: Duration::from_secs(2),
                allow_plaintext_loopback: true,
                root_certificate_pem: None,
            },
            control,
        )
        .unwrap()
    }

    fn evict_owned_keys(&self, namespace: &str, member: &str) {
        let scope = format!("{namespace}\0community.example");
        let prefix = format!(
            "cfrm:{{{}}}",
            BASE64URL_NOPAD.encode(&Sha256::digest(scope.as_bytes()))
        );
        let mut connection = redis::Client::open(self.url.as_str())
            .unwrap()
            .get_connection()
            .unwrap();
        // This endpoint was proven to be our child, and all names are exact keys
        // in this test's namespace. Never flush a database or match external keys.
        for suffix in [format!("profile:{member}"), "catalog".into(), "live".into()] {
            let _: usize = redis::cmd("DEL")
                .arg(format!("{prefix}:{suffix}"))
                .query(&mut connection)
                .unwrap();
        }
    }
}

impl Drop for OwnedServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn actual_cache_eviction_and_reopen_preserve_quota_and_allow_exact_repair() {
    let Some(server) = OwnedServer::start() else {
        return;
    };
    let database = server.directory.path().join("control.sqlite");
    let f = Fixture::new();
    let service = DiscoveryService::new(
        f.trust.clone(),
        fixtures::limits(),
        server.store("eviction", &database),
    )
    .unwrap();
    let first = fixtures::publication(&f, 5, 1, 1, 31);
    service.execute(&first, 110).unwrap();
    assert!(matches!(
        service.execute(&fixtures::fetch(&f, 2, 110, 5), 110),
        Ok(DiscoveryResponse::Profile {
            publication: Some(_)
        })
    ));
    server.evict_owned_keys("eviction", &member_id(5));
    assert_eq!(
        service.execute(&fixtures::fetch(&f, 3, 110, 5), 110),
        Ok(DiscoveryResponse::Profile { publication: None })
    );
    assert_eq!(service.execute(&first, 110), Ok(DiscoveryResponse::Updated));
    let second = fixtures::publication(&f, 5, 2, 4, 32);
    service.execute(&second, 110).unwrap();
    server.evict_owned_keys("eviction", &member_id(5));
    drop(service);
    let service = DiscoveryService::new(
        f.trust.clone(),
        fixtures::limits(),
        server.store("eviction", &database),
    )
    .unwrap();
    service.execute(&second, 110).unwrap();
    assert_eq!(
        service.execute(&fixtures::publication(&f, 5, 3, 5, 33), 110),
        Err(Error::Capacity)
    );
    match service
        .execute(&fixtures::fetch(&f, 6, 110, 5), 110)
        .unwrap()
    {
        DiscoveryResponse::Profile {
            publication: Some(value),
        } => assert_eq!(value.envelope.sequence, 2),
        other => panic!("unexpected {other:?}"),
    }
    // An older successful retry must not restore its old bytes over revision2.
    service.execute(&first, 110).unwrap();
    match service
        .execute(&fixtures::fetch(&f, 7, 110, 5), 110)
        .unwrap()
    {
        DiscoveryResponse::Profile {
            publication: Some(value),
        } => assert_eq!(value.envelope.sequence, 2),
        other => panic!("unexpected {other:?}"),
    }
    server.evict_owned_keys("eviction", &member_id(5));
    // Both publish credits were consumed, and the original signed request has
    // now expired. Repairing the exact current bytes must still be possible.
    assert_eq!(service.execute(&second, 131), Err(Error::Expired));
    let mut repair = second;
    repair.request_id = encoded(8);
    repair.issued_at = 131;
    repair.expires_at = 151;
    if let DiscoveryOperation::Publish { lease, .. } = &mut repair.operation {
        lease.sequence = 3;
        lease.expires_at = 191;
    }
    fixtures::sign(&f.device, &mut repair);
    service.execute(&repair, 131).unwrap();
    match service
        .execute(&fixtures::fetch(&f, 9, 131, 5), 131)
        .unwrap()
    {
        DiscoveryResponse::Profile {
            publication: Some(value),
        } => {
            assert_eq!(value.envelope.sequence, 2);
            assert_eq!(value.envelope.expires_at, 400);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn independent_replica_connections_share_durable_race_and_device_guards() {
    let Some(server) = OwnedServer::start() else {
        return;
    };
    let database = server.directory.path().join("control.sqlite");
    let f = Fixture::new();
    let a = Arc::new(
        DiscoveryService::new(
            f.trust.clone(),
            fixtures::limits(),
            server.store("replicas", &database),
        )
        .unwrap(),
    );
    let b = Arc::new(
        DiscoveryService::new(
            f.trust.clone(),
            fixtures::limits(),
            server.store("replicas", &database),
        )
        .unwrap(),
    );
    let barrier = Arc::new(Barrier::new(2));
    let jobs: Vec<_> = [
        (a.clone(), fixtures::publication(&f, 5, 1, 1, 31)),
        (b.clone(), fixtures::publication(&f, 5, 1, 2, 32)),
    ]
    .into_iter()
    .map(|(service, request)| {
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            service.execute(&request, 110)
        })
    })
    .collect();
    let results: Vec<_> = jobs.into_iter().map(|job| job.join().unwrap()).collect();
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
    let second = SigningKey::from_bytes(&[42; 32]);
    let heartbeat = fixtures::operation(
        &f,
        &second,
        5,
        22,
        3,
        110,
        DiscoveryOperation::Heartbeat {
            lease: DiscoveryLease {
                lease_id: encoded(22),
                sequence: 1,
                expires_at: 160,
            },
        },
    );
    b.execute(&heartbeat, 110).unwrap();
    let disconnect = fixtures::operation(
        &f,
        &f.device,
        5,
        11,
        4,
        111,
        DiscoveryOperation::Disconnect {
            lease_id: encoded(11),
            sequence: 2,
        },
    );
    a.execute(&disconnect, 111).unwrap();
    assert!(matches!(
        b.execute(&fixtures::fetch(&f, 5, 159, 5), 159),
        Ok(DiscoveryResponse::Profile {
            publication: Some(_)
        })
    ));
    assert_eq!(
        b.execute(&fixtures::fetch(&f, 6, 160, 5), 160),
        Ok(DiscoveryResponse::Profile { publication: None })
    );
}

#[test]
fn actual_query_continues_after_empty_bounded_scan_and_rejects_rediscovered_read_replay() {
    let Some(server) = OwnedServer::start() else {
        return;
    };
    let database = server.directory.path().join("control.sqlite");
    let f = Fixture::new();
    let mut limits = fixtures::limits();
    limits.max_scan = 1;
    limits.max_results = 1;
    let service = DiscoveryService::new(
        f.trust.clone(),
        limits,
        server.store("pagination", &database),
    )
    .unwrap();
    service
        .execute(&fixtures::publication(&f, 5, 1, 1, 31), 110)
        .unwrap();
    service
        .execute(&fixtures::publication(&f, 6, 1, 2, 32), 110)
        .unwrap();
    let query = fixtures::operation(
        &f,
        &f.device,
        5,
        11,
        3,
        110,
        DiscoveryOperation::Query {
            filters: BTreeMap::from([("ageBand".into(), 7)]),
            limit: 1,
            after: None,
        },
    );
    let cursor = match service.execute(&query, 110).unwrap() {
        DiscoveryResponse::Page {
            entries,
            next_cursor,
        } => {
            assert!(entries.is_empty());
            next_cursor.expect("bounded scan must advance")
        }
        other => panic!("unexpected {other:?}"),
    };
    let next = fixtures::operation(
        &f,
        &f.device,
        5,
        11,
        4,
        110,
        DiscoveryOperation::Query {
            filters: BTreeMap::from([("ageBand".into(), 7)]),
            limit: 1,
            after: Some(cursor),
        },
    );
    assert_eq!(
        service.execute(&next, 110),
        Ok(DiscoveryResponse::Page {
            entries: vec![],
            next_cursor: None
        })
    );
    server.evict_owned_keys("pagination", &member_id(5));
    assert_eq!(service.execute(&query, 110), Err(Error::Replay));
}

#[test]
fn actual_cache_query_byte_budget_preserves_all_matching_members() {
    let Some(server) = OwnedServer::start() else {
        return;
    };
    let database = server.directory.path().join("control.sqlite");
    let f = Fixture::new();
    let mut limits = fixtures::limits();
    limits.max_record_bytes = 3000;
    limits.max_response_bytes = 3000;
    let service = DiscoveryService::new(
        f.trust.clone(),
        limits,
        server.store("page-bytes", &database),
    )
    .unwrap();
    let mut expected = Vec::new();
    for member in 5..25 {
        service
            .execute(&fixtures::publication(&f, member, 1, 1, 31), 110)
            .unwrap();
        expected.push(member_id(member));
    }
    expected.sort();
    let mut received = Vec::new();
    let mut after = None;
    let mut pages = 0;
    loop {
        pages += 1;
        assert!(pages <= 20, "cursor must advance");
        let query = fixtures::operation(
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
        let response = service.execute(&query, 110).unwrap();
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
    assert!(pages > 1);
    assert_eq!(received, expected);
}
