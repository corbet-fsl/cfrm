//! Dynamic communities. A request's Host selects a community through the
//! registry; the forum keeps one isolated owner per live community and nothing
//! per-community is configured. The registry is the only source of what the
//! forum trusts about a community (its key ring and origins): never a feed
//! response or a member request.
use crate::{ErrorCode, runtime::Handle};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::Mutex, task::JoinHandle};

pub type Fut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    BeingCreated,
    Live,
    Ending,
    Ended,
}

/// What the registry says about one community. `id` is the registry's fresh,
/// never reused identifier (32 lowercase hex digits); it names all forum state.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub id: String,
    pub state: State,
    /// Exact browser origins allowed to call this community's forum.
    pub origins: Vec<String>,
    /// Where the community publishes its signed feed.
    pub trust_origin: String,
    pub key_ring: Vec<u8>,
    pub minimum_revision: u64,
    pub ring_revision: u64,
}
impl Record {
    pub fn valid(&self) -> bool {
        valid_id(&self.id)
            && !self.origins.is_empty()
            && self.origins.len() <= 4
            && self.origins.iter().all(|origin| {
                url::Url::parse(origin).is_ok_and(|u| {
                    u.scheme() == "https" && u.origin().ascii_serialization() == *origin
                })
            })
            && !self.key_ring.is_empty()
    }
}

pub fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
}

/// Registry read port. It answers "who is this host" and "which communities
/// are over"; it never reveals members.
pub trait Directory: Send + Sync {
    /// `Some` only for a community whose host currently resolves.
    fn by_host(&self, host: &str) -> Fut<'_, Result<Option<Record>, ErrorCode>>;
    /// Identifiers of every community that is ending or ended.
    fn finished(&self) -> Fut<'_, Result<Vec<String>, ErrorCode>>;
}

/// A running community owner.
pub struct Launched {
    pub handle: Handle,
    pub worker: JoinHandle<()>,
    pub follower: JoinHandle<()>,
    /// Withdraws native proof processes; used only when the worker must be aborted.
    pub cancel: Box<dyn Fn() + Send + Sync>,
}
/// Starts a community's owner and deletes all of its state.
pub trait Backend: Send + Sync {
    fn launch(&self, record: &Record) -> Fut<'_, Result<Launched, ErrorCode>>;
    /// Idempotent: removes every stored key of the community.
    fn purge(&self, id: &str) -> Fut<'_, Result<(), ErrorCode>>;
}

#[derive(Clone)]
pub struct Tenant {
    pub handle: Handle,
    pub origins: Vec<String>,
}

struct AbortOnDrop(JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct Running {
    record: Record,
    handle: Handle,
    worker: JoinHandle<()>,
    cancel: Box<dyn Fn() + Send + Sync>,
    _follower: AbortOnDrop,
}
impl Running {
    /// An owner whose worker or feed follower ended is replaced, never reused.
    fn alive(&self) -> bool {
        !self.worker.is_finished() && !self._follower.0.is_finished()
    }
    /// Ingress is already gone: drain what was admitted, then force the end.
    async fn finish(self, grace: Duration) {
        let Self {
            handle,
            mut worker,
            cancel,
            _follower,
            ..
        } = self;
        drop(_follower);
        drop(handle);
        if tokio::time::timeout(grace, &mut worker).await.is_err() {
            // Revoke the native process owners before the abort: synchronous
            // native polling cannot be preempted.
            cancel();
            worker.abort();
        }
    }
}

#[derive(Default)]
struct Inner {
    running: BTreeMap<String, Running>,
    hosts: BTreeMap<String, (String, Instant)>,
    misses: BTreeMap<String, Instant>,
    purged: BTreeSet<String>,
}
const MISS_LIMIT: usize = 1024;
const PURGED_LIMIT: usize = 65_536;

pub struct Tenants {
    directory: Arc<dyn Directory>,
    backend: Arc<dyn Backend>,
    /// Upper bound on how long a stale registry answer is used. An ended
    /// community stops being served within this time.
    recheck: Duration,
    grace: Duration,
    maximum: usize,
    inner: Mutex<Inner>,
}
impl Tenants {
    pub fn new(
        directory: Arc<dyn Directory>,
        backend: Arc<dyn Backend>,
        recheck: Duration,
        grace: Duration,
        maximum: usize,
    ) -> Result<Self, ErrorCode> {
        if maximum == 0 || grace.is_zero() {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(Self {
            directory,
            backend,
            recheck,
            grace,
            maximum,
            inner: Mutex::default(),
        })
    }

    /// Owner for the community at `host`, started on first use.
    pub async fn resolve(&self, host: &str) -> Result<Tenant, ErrorCode> {
        if !valid_host(host) {
            return Err(ErrorCode::Host);
        }
        let now = Instant::now();
        {
            let inner = self.inner.lock().await;
            if inner
                .misses
                .get(host)
                .is_some_and(|at| now.duration_since(*at) < self.recheck)
            {
                return Err(ErrorCode::Host);
            }
            if let Some(running) = inner
                .hosts
                .get(host)
                .filter(|(_, at)| now.duration_since(*at) < self.recheck)
                .and_then(|(id, _)| inner.running.get(id))
                .filter(|running| running.alive())
            {
                return Ok(tenant(running));
            }
        }
        let found = self.directory.by_host(host).await?;
        let mut inner = self.inner.lock().await;
        let record = match found {
            Some(record) if record.state == State::Live && record.valid() => record,
            _ => {
                let stopped = inner
                    .hosts
                    .remove(host)
                    .and_then(|(id, _)| detach(&mut inner, &id));
                if inner.misses.len() >= MISS_LIMIT {
                    inner.misses.clear();
                }
                inner.misses.insert(host.to_owned(), now);
                drop(inner);
                if let Some(running) = stopped {
                    running.finish(self.grace).await;
                }
                return Err(ErrorCode::Host);
            }
        };
        // A changed registry answer (rotated key ring, new origins) restarts the
        // owner so that nothing keeps the old trust.
        let replaced = match inner.running.get(&record.id) {
            Some(running) if running.record == record && running.alive() => None,
            _ => detach(&mut inner, &record.id),
        };
        if let Some(old) = replaced {
            old.finish(self.grace).await;
        }
        if !inner.running.contains_key(&record.id) {
            if inner.running.len() >= self.maximum {
                return Err(ErrorCode::Capacity);
            }
            let launched = self.backend.launch(&record).await?;
            inner.running.insert(
                record.id.clone(),
                Running {
                    record: record.clone(),
                    handle: launched.handle,
                    worker: launched.worker,
                    cancel: launched.cancel,
                    _follower: AbortOnDrop(launched.follower),
                },
            );
        }
        inner.misses.remove(host);
        inner
            .hosts
            .insert(host.to_owned(), (record.id.clone(), now));
        Ok(tenant(&inner.running[&record.id]))
    }

    /// Process shutdown: stop every community, draining admitted work.
    pub async fn stop_all(&self) {
        let all = std::mem::take(&mut self.inner.lock().await.running);
        self.inner.lock().await.hosts.clear();
        for (_, running) in all {
            running.finish(self.grace).await;
        }
    }

    /// Stop serving a community and delete all of its state. Safe to repeat.
    pub async fn end(&self, id: &str) -> Result<(), ErrorCode> {
        if !valid_id(id) {
            return Err(ErrorCode::InvalidRequest);
        }
        let stopped = detach(&mut *self.inner.lock().await, id);
        if let Some(running) = stopped {
            running.finish(self.grace).await;
        }
        self.backend.purge(id).await?;
        let mut inner = self.inner.lock().await;
        if inner.purged.len() >= PURGED_LIMIT {
            inner.purged.clear();
        }
        inner.purged.insert(id.to_owned());
        Ok(())
    }

    /// Learn from the registry which communities are over and end each one
    /// that this process has not already purged. Returns how many were purged.
    pub async fn sweep(&self) -> Result<usize, ErrorCode> {
        let mut count = 0;
        for id in self.directory.finished().await? {
            if !valid_id(&id) || self.inner.lock().await.purged.contains(&id) {
                continue;
            }
            self.end(&id).await?;
            count += 1;
        }
        Ok(count)
    }
}

fn tenant(running: &Running) -> Tenant {
    Tenant {
        handle: running.handle.clone(),
        origins: running.record.origins.clone(),
    }
}
/// Remove a running owner and every host cache entry that points at it.
fn detach(inner: &mut Inner, id: &str) -> Option<Running> {
    inner.hosts.retain(|_, (host_id, _)| host_id != id);
    inner.running.remove(id)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex as Std;

    #[derive(Default)]
    pub(crate) struct Registry {
        pub(crate) records: Std<BTreeMap<String, Record>>,
        pub(crate) finished: Std<Vec<String>>,
        pub(crate) fail: Std<bool>,
        pub(crate) lookups: Std<usize>,
    }
    impl Directory for Registry {
        fn by_host(&self, host: &str) -> Fut<'_, Result<Option<Record>, ErrorCode>> {
            let host = host.to_owned();
            Box::pin(async move {
                *self.lookups.lock().unwrap() += 1;
                if *self.fail.lock().unwrap() {
                    return Err(ErrorCode::AuthorityUnavailable);
                }
                Ok(self.records.lock().unwrap().get(&host).cloned())
            })
        }
        fn finished(&self) -> Fut<'_, Result<Vec<String>, ErrorCode>> {
            Box::pin(async move { Ok(self.finished.lock().unwrap().clone()) })
        }
    }
    #[derive(Default)]
    pub(crate) struct Fake {
        launched: Std<Vec<String>>,
        short: Std<bool>,
        purged: Std<Vec<String>>,
    }
    impl Backend for Fake {
        fn launch(&self, record: &Record) -> Fut<'_, Result<Launched, ErrorCode>> {
            let id = record.id.clone();
            Box::pin(async move {
                self.launched.lock().unwrap().push(id);
                let short = *self.short.lock().unwrap();
                let (handle, receiver) = Handle::stalled();
                Ok(Launched {
                    handle,
                    worker: tokio::spawn(async move {
                        let _keep = receiver;
                        if !short {
                            std::future::pending::<()>().await;
                        }
                    }),
                    follower: tokio::spawn(std::future::pending::<()>()),
                    cancel: Box::new(|| {}),
                })
            })
        }
        fn purge(&self, id: &str) -> Fut<'_, Result<(), ErrorCode>> {
            let id = id.to_owned();
            Box::pin(async move {
                self.purged.lock().unwrap().push(id);
                Ok(())
            })
        }
    }

    pub(crate) const A: &str = "0123456789abcdef0123456789abcdef";
    pub(crate) const B: &str = "fedcba9876543210fedcba9876543210";
    pub(crate) fn record(id: &str, state: State) -> Record {
        Record {
            id: id.into(),
            state,
            origins: vec![format!("https://{}.example.test", &id[..8])],
            trust_origin: "https://trust.example.test".into(),
            key_ring: vec![1],
            minimum_revision: 1,
            ring_revision: 1,
        }
    }
    pub(crate) fn setup(recheck: Duration, maximum: usize) -> (Arc<Registry>, Arc<Fake>, Tenants) {
        let registry = Arc::new(Registry::default());
        let backend = Arc::new(Fake::default());
        let tenants = Tenants::new(
            registry.clone(),
            backend.clone(),
            recheck,
            Duration::from_millis(50),
            maximum,
        )
        .unwrap();
        (registry, backend, tenants)
    }
    pub(crate) fn put(registry: &Registry, host: &str, record: Record) {
        registry.records.lock().unwrap().insert(host.into(), record);
    }

    #[test]
    fn records_and_identifiers_are_validated() {
        assert!(record(A, State::Live).valid());
        let mut short = record(A, State::Live);
        short.id = "short".into();
        assert!(!short.valid());
        short.id = A.to_uppercase();
        assert!(!short.valid());
        let mut bad = record(A, State::Live);
        bad.origins = vec!["http://x.example.test".into()];
        assert!(!bad.valid());
        bad.origins = vec![];
        assert!(!bad.valid());
        bad.origins = vec!["https://x.example.test/path".into()];
        assert!(!bad.valid());
        let mut bad = record(A, State::Live);
        bad.key_ring.clear();
        assert!(!bad.valid());
        assert!(valid_host("a.b-c.example"));
        for host in ["", "A.example", "a:443", &"a".repeat(254)] {
            assert!(!valid_host(host), "{host}");
        }
        assert!(
            Tenants::new(
                Arc::new(Registry::default()),
                Arc::new(Fake::default()),
                Duration::ZERO,
                Duration::from_secs(1),
                0
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn a_live_community_is_started_once_and_cached() {
        let (registry, backend, tenants) = setup(Duration::from_secs(60), 4);
        put(&registry, "a.example.test", record(A, State::Live));
        put(&registry, "vault.a.example.test", record(A, State::Live));
        let first = tenants.resolve("a.example.test").await.unwrap();
        assert_eq!(first.origins, vec!["https://01234567.example.test"]);
        tenants.resolve("a.example.test").await.unwrap();
        tenants.resolve("vault.a.example.test").await.unwrap();
        assert_eq!(*registry.lookups.lock().unwrap(), 2);
        assert_eq!(*backend.launched.lock().unwrap(), vec![A]);
    }

    #[tokio::test]
    async fn unknown_unready_and_invalid_hosts_are_refused_and_remembered() {
        let (registry, backend, tenants) = setup(Duration::from_secs(60), 4);
        assert_eq!(tenants.resolve("BAD").await.err(), Some(ErrorCode::Host));
        assert_eq!(
            tenants.resolve("no.example.test").await.err(),
            Some(ErrorCode::Host)
        );
        tenants.resolve("no.example.test").await.err();
        assert_eq!(*registry.lookups.lock().unwrap(), 1);
        for (host, state) in [
            ("c.example.test", State::BeingCreated),
            ("e.example.test", State::Ended),
        ] {
            put(&registry, host, record(A, state));
            assert_eq!(tenants.resolve(host).await.err(), Some(ErrorCode::Host));
        }
        let mut invalid = record(B, State::Live);
        invalid.key_ring.clear();
        put(&registry, "i.example.test", invalid);
        assert_eq!(
            tenants.resolve("i.example.test").await.err(),
            Some(ErrorCode::Host)
        );
        assert!(backend.launched.lock().unwrap().is_empty());
        registry.records.lock().unwrap().clear();
        *registry.fail.lock().unwrap() = true;
        assert_eq!(
            tenants.resolve("z.example.test").await.err(),
            Some(ErrorCode::AuthorityUnavailable)
        );
    }

    #[tokio::test]
    async fn a_community_that_stops_resolving_is_stopped() {
        let (registry, backend, tenants) = setup(Duration::ZERO, 4);
        put(&registry, "a.example.test", record(A, State::Live));
        tenants.resolve("a.example.test").await.unwrap();
        registry.records.lock().unwrap().clear();
        assert_eq!(
            tenants.resolve("a.example.test").await.err(),
            Some(ErrorCode::Host)
        );
        // Gone is not purged by a lookup: only the registry's ended list does that.
        assert!(backend.purged.lock().unwrap().is_empty());
        put(&registry, "a.example.test", record(A, State::Live));
        tenants.resolve("a.example.test").await.unwrap();
        assert_eq!(backend.launched.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn changed_trust_restarts_the_owner() {
        let (registry, backend, tenants) = setup(Duration::ZERO, 4);
        put(&registry, "a.example.test", record(A, State::Live));
        tenants.resolve("a.example.test").await.unwrap();
        tenants.resolve("a.example.test").await.unwrap();
        assert_eq!(backend.launched.lock().unwrap().len(), 1);
        let mut rotated = record(A, State::Live);
        rotated.ring_revision = 2;
        put(&registry, "a.example.test", rotated);
        tenants.resolve("a.example.test").await.unwrap();
        assert_eq!(backend.launched.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn the_number_of_running_communities_is_bounded() {
        let (registry, _, tenants) = setup(Duration::from_secs(60), 1);
        put(&registry, "a.example.test", record(A, State::Live));
        put(&registry, "b.example.test", record(B, State::Live));
        tenants.resolve("a.example.test").await.unwrap();
        assert_eq!(
            tenants.resolve("b.example.test").await.err(),
            Some(ErrorCode::Capacity)
        );
    }

    #[tokio::test]
    async fn ending_a_community_stops_it_and_deletes_its_state_once() {
        let (registry, backend, tenants) = setup(Duration::from_secs(60), 4);
        put(&registry, "a.example.test", record(A, State::Live));
        tenants.resolve("a.example.test").await.unwrap();
        assert_eq!(tenants.end("nope").await, Err(ErrorCode::InvalidRequest));
        *registry.finished.lock().unwrap() = vec![A.into(), "bad".into()];
        assert_eq!(tenants.sweep().await, Ok(1));
        assert_eq!(tenants.sweep().await, Ok(0));
        assert_eq!(*backend.purged.lock().unwrap(), vec![A]);
        // The cached host no longer reaches a running owner.
        registry.records.lock().unwrap().clear();
        *registry.lookups.lock().unwrap() = 0;
        assert_eq!(
            tenants.resolve("a.example.test").await.err(),
            Some(ErrorCode::Host)
        );
        assert_eq!(*registry.lookups.lock().unwrap(), 1);
        tenants.stop_all().await;
        // An explicit end for a community that never ran still purges.
        tenants.end(B).await.unwrap();
        assert_eq!(backend.purged.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn an_owner_that_ended_is_replaced() {
        let (registry, backend, tenants) = setup(Duration::from_secs(60), 4);
        put(&registry, "a.example.test", record(A, State::Live));
        *backend.short.lock().unwrap() = true;
        tenants.resolve("a.example.test").await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        *backend.short.lock().unwrap() = false;
        tenants.resolve("a.example.test").await.unwrap();
        assert_eq!(backend.launched.lock().unwrap().len(), 2);
    }
}
