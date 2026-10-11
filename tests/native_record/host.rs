//! Actual actor, scoped store and TCP HTTP adapter, with independently owned
//! native cancellation retained exactly as the production host retains it.
use super::*;
use std::{
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use tokio::net::TcpStream;

#[derive(Clone)]
pub(super) struct Time(pub Arc<AtomicU64>);
impl Clock for Time {
    fn now(&self) -> Result<u64, cmmr::Error> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}
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
pub(super) struct Host {
    pub address: SocketAddr,
    pub handle: runtime::Handle,
    pub actor: tokio::task::JoinHandle<()>,
    pub storage: cvtl::Volatile<Time>,
    pub cancellation: cgth::accounting::verification::NativeExtensionCancellation,
    pub clock: Time,
    network: tokio::task::JoinHandle<()>,
}
impl Drop for Host {
    fn drop(&mut self) {
        self.storage.close();
        self.cancellation.cancel();
        self.network.abort();
        self.actor.abort();
    }
}
impl Host {
    pub async fn new(native: &Fixture, executable: PathBuf) -> Self {
        let clock = Time(Arc::new(AtomicU64::new(native.now * 1000)));
        let assurance = csrn::Assurance::new(
            cchr::Configuration {
                origin: "https://identity.example.test".into(),
                community: native.material.community.clone(),
                key_ring: native.trusted_key_ring.clone(),
                minimum_revision: 1,
                ring_revision: 0,
            },
            csrn::feed::Config {
                retry_entropy: 15,
                refresh_seconds: 1,
                poll_seconds: 1,
                request_seconds: 30,
                initial_backoff_seconds: 1,
                maximum_backoff_seconds: 10,
                maximum_staleness_seconds: 60,
            },
        )
        .unwrap();
        let storage = cvtl::Volatile::memory(
            cmmr::Scope::new(&native.material.community, "native-http").unwrap(),
            cmmr::Limits {
                records: 128,
                value_bytes: 1024 * 1024,
                batch: 4,
                indexes_per_record: 4,
                page: 8,
                ttl_ms: 600_000,
            },
            clock.clone(),
        )
        .unwrap();
        let throttle = cthl::Throttle::new(
            &native.material.community,
            actions().into_iter().map(|action| {
                (
                    action.name,
                    cthl::Limit::new(1000, Duration::from_secs(1)).unwrap(),
                )
            }),
            cthl::MemoryStore::new(NonZeroUsize::new(128).unwrap()),
        )
        .unwrap();
        let verifier = native.native(executable);
        let cancellation = verifier.cancellation();
        let service = runtime::Service::new(
            assurance,
            runtime::Parts {
                storage: storage.clone(),
                clock: clock.clone(),
                tokens: Random,
                throttle,
            },
            runtime::Configuration {
                community: native.material.community.clone(),
                incarnation: "native-http".into(),
                admission_action: g1::ACTION.into(),
                origins: vec![g1::ORIGIN.into()],
                maximum_snapshot_age: 300,
                request_bytes: 1_048_576,
                presence: cswb::Limits {
                    lease_ms: 300_000,
                    publication_bytes: cpfl::MAX_PROFILE_BYTES,
                    ciphertext_bytes: cpfl::MAX_PROFILE_BYTES,
                },
                lookup: cgth::clkp::LookupLimits {
                    candidates: 3,
                    publication_bytes: cpfl::MAX_PROFILE_BYTES * 3,
                },
                room_epoch: runtime::RoomEpochConfiguration {
                    epoch: 1,
                    valid_from_ms: native.now * 1000,
                    valid_until_ms: (native.now + 3) * 1000,
                },
                rooms: cgth::cmbl::Limits {
                    connections: 4,
                    relay_messages: 4,
                    message_bytes: 1024,
                    lifetime_ms: 10_000,
                    proof_bytes: cgth::cmbl::passes::MAX_PROOF_BYTES,
                    operation_receipts: 16,
                },
            },
            g1::clean,
        )
        .unwrap()
        .with_accounting(
            cgth::accounting::Configuration {
                community: native.material.community.clone(),
                period_key: g1::PERIOD_KEY.into(),
                period_seconds: native.trusted_period_seconds,
            },
            verifier,
            cgth::accounting::verification::ExtensionLimits {
                global_burst: 1000,
                subject_burst: 1000,
                replenish: Duration::from_secs(1),
                maximum_keys: NonZeroUsize::new(32).unwrap(),
            },
        )
        .unwrap();
        let (handle, actor) = service.spawn(16, Duration::from_millis(10)).unwrap();
        let request = handle.start_feed().await.unwrap();
        handle
            .complete_feed(
                request.id(),
                serde_json::to_vec(&g1::feed(native, 10_000, 1)).unwrap(),
                false,
            )
            .await
            .unwrap();
        let app = http::router_with(
            http::Limits {
                hosts: vec!["forum.example.test".into()],
                origins: vec![g1::ORIGIN.into()],
                body_bytes: 1_048_576,
                concurrent: 8,
                anonymous_concurrent: 2,
                body_timeout: Duration::from_secs(30),
                request_timeout: Duration::from_secs(120),
                source: cfrm::bucket::Bucket { burst: 100_000, replenish: Duration::from_millis(1), keys: 16 },
                session: cfrm::bucket::Bucket { burst: 100_000, replenish: Duration::from_millis(1), keys: 1024 },
            },
            handle.clone(),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let network = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            address,
            handle,
            actor,
            storage,
            cancellation,
            clock,
            network,
        }
    }
}

/// The original maintained verifier executes unchanged after the deliberate
/// host scheduling delay. This wrapper supplies no proof or acceptance result.
pub(super) struct Delay {
    _directory: tempfile::TempDir,
    pub executable: PathBuf,
    pub pid: PathBuf,
    control: PathBuf,
}
impl Delay {
    pub fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("delayed-native");
        let pid = directory.path().join("pid");
        let control = directory.path().join("delay");
        let real = PathBuf::from(
            std::env::var_os("CBLC_BB").expect("The genuine CBLC native worker is required"),
        )
        .canonicalize()
        .unwrap();
        let quoted = |path: &Path| serde_json::to_string(path.to_str().unwrap()).unwrap();
        std::fs::write(&executable, format!("#!/usr/bin/env python3\nimport os,sys,time\nopen({},'w').write(str(os.getpid()))\ntime.sleep(float(open({}).read()))\nreal={}\nos.execv(real,[real,*sys.argv[1:]])\n", quoted(&pid), quoted(&control), quoted(&real))).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&control, "0").unwrap();
        Self {
            _directory: directory,
            executable,
            pid,
            control,
        }
    }
    pub fn seconds(&self, seconds: u64) {
        if self.pid.exists() {
            std::fs::remove_file(&self.pid).unwrap();
        }
        std::fs::write(&self.control, seconds.to_string()).unwrap();
    }
    pub async fn started(&self) -> u32 {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Ok(bytes) = std::fs::read_to_string(&self.pid) {
                    if let Ok(pid) = bytes.parse() {
                        break pid;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("The actual owned native process must start")
    }
}

pub(super) async fn exchange(
    address: SocketAddr,
    method: &str,
    path: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: forum.example.test\r\nOrigin: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", g1::ORIGIN, body.len()).into_bytes();
    request.extend_from_slice(body);
    let stream = TcpStream::connect(address).await.unwrap();
    let mut written = 0;
    while written < request.len() {
        stream.writable().await.unwrap();
        match stream.try_write(&request[written..]) {
            Ok(0) => panic!("HTTP writer closed"),
            Ok(count) => written += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("HTTP write: {error}"),
        }
    }
    let mut response = Vec::new();
    loop {
        stream.readable().await.unwrap();
        let mut bytes = [0; 8192];
        match stream.try_read(&mut bytes) {
            Ok(0) => break,
            Ok(count) => response.extend_from_slice(&bytes[..count]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("HTTP read: {error}"),
        }
        assert!(response.len() <= 1_048_576);
    }
    let cut = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    let headers = std::str::from_utf8(&response[..cut])
        .unwrap()
        .to_ascii_lowercase();
    assert!(
        !headers.contains("transfer-encoding: chunked"),
        "The finite fixture response must retain its length framing"
    );
    response[cut..].to_vec()
}
pub(super) async fn call(address: SocketAddr, request: Request) -> Result<Reply, ErrorCode> {
    let path = format!("/v1/{}", request.info().name);
    let bytes = exchange(
        address,
        "POST",
        &path,
        &serde_json::to_vec(&Call::new(request)).unwrap(),
    )
    .await;
    if let Ok(failure) = serde_json::from_slice::<Failure>(&bytes) {
        Err(failure.error)
    } else {
        Ok(serde_json::from_slice(&bytes).unwrap())
    }
}
