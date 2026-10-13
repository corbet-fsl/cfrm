use cfrm::{ErrorCode, http, runtime, tenant};
use cgth::{clkp, cmbl, cmmr, cswb, cthl};
use cmmr::Clock;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    io::Read,
    net::SocketAddr,
    num::NonZeroUsize,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

mod accounting;
#[cfg(feature = "ohttp")]
mod ohttp;
mod registry;

#[derive(clap::Parser)]
pub struct Arguments {
    #[command(subcommand)]
    command: Command,
}
#[derive(clap::Subcommand)]
enum Command {
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
}

/// No defaults: production timing, scope, trust and storage are explicit inputs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    bind: SocketAddr,
    admission_action: String,
    accounting: accounting::Configuration,
    incarnation: String,
    /// Where communities come from. Nothing per-community is configured.
    registry: registry::Configuration,
    /// Explicit public DER roots supplement the maintained TLS root store.
    trust_roots_der: Vec<Vec<u8>>,
    refresh_seconds: u64,
    poll_seconds: u64,
    request_seconds: u64,
    initial_backoff_seconds: u64,
    maximum_backoff_seconds: u64,
    maximum_staleness_seconds: u64,
    maximum_snapshot_age: u64,
    storage: Storage,
    /// Oblivious HTTP gateway; absent means direct HTTPS only.
    #[cfg(feature = "ohttp")]
    #[serde(default)]
    ohttp: Option<ohttp::Configuration>,
    storage_limits: cmmr::Limits,
    maximum_lease_ms: u64,
    publication_bytes: usize,
    ciphertext_bytes: usize,
    candidate_count: usize,
    page_publication_bytes: usize,
    room_epoch: runtime::RoomEpochConfiguration,
    room_connections: usize,
    room_relay_messages: usize,
    room_message_bytes: usize,
    room_lifetime_ms: u64,
    room_proof_bytes: usize,
    room_operation_receipts: usize,
    request_bytes: usize,
    http_concurrent: usize,
    /// Share of `http_concurrent` reserved for pre-session actions.
    http_anonymous_concurrent: usize,
    http_body_timeout_ms: u64,
    /// Bound for one owner call; slow owners cannot hold a connection longer.
    http_request_timeout_ms: u64,
    /// RAM-only per-source and per-session token buckets.
    source_bucket: BucketConfiguration,
    session_bucket: BucketConfiguration,
    command_capacity: usize,
    maintenance_ms: u64,
    /// Graceful command-drain budget. Forced cleanup cancels and reaps native work.
    shutdown_ms: u64,
    throttle_capacity: NonZeroUsize,
    throttle: BTreeMap<String, Rate>,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Storage {
    Memory,
    Valkey { url: String, timeout_ms: u64 },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BucketConfiguration {
    burst: u32,
    replenish_ms: u64,
    keys: usize,
}
impl BucketConfiguration {
    fn bucket(&self) -> cfrm::bucket::Bucket {
        cfrm::bucket::Bucket {
            burst: self.burst,
            replenish: Duration::from_millis(self.replenish_ms),
            keys: self.keys,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rate {
    burst: u32,
    replenish_ms: u64,
}

#[derive(Clone, Default)]
struct WallClock(Arc<AtomicU64>);
impl Clock for WallClock {
    fn now(&self) -> Result<u64, cmmr::Error> {
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| cmmr::Error::Unavailable)?
                .as_millis(),
        )
        .map_err(|_| cmmr::Error::Invalid)?;
        if now > cmmr::MAX_TIME || now < self.0.fetch_max(now, Ordering::SeqCst) {
            return Err(cmmr::Error::ClockRegression);
        }
        Ok(now)
    }
}
#[derive(Clone)]
struct Random;
impl cswb::Tokens for Random {
    fn next(&self) -> Result<[u8; 16], cswb::Error> {
        let mut value = [0; 16];
        getrandom::fill(&mut value).map_err(|_| cswb::Error::Invalid)?;
        Ok(value)
    }
}
fn entropy() -> Result<u64, ErrorCode> {
    let mut value = [0; 8];
    getrandom::fill(&mut value).map_err(|_| ErrorCode::AuthorityUnavailable)?;
    Ok(u64::from_le_bytes(value))
}

/// Process-wide inputs shared by every community this process serves.
struct Shared {
    configuration: Configuration,
    clock: WallClock,
    /// Present for Valkey storage; every community opens its own scope on it.
    network: Option<(Arc<cvtl::RedisNetwork>, redis::aio::MultiplexedConnection)>,
    artifacts: cgth::accounting::artifacts::ExtensionArtifacts,
}

pub async fn run(arguments: Arguments) -> Result<(), ErrorCode> {
    let Command::Serve { config } = arguments.command;
    let file = std::fs::File::open(config).map_err(|_| ErrorCode::InvalidRequest)?;
    let mut bytes = Vec::new();
    file.take(1_048_577)
        .read_to_end(&mut bytes)
        .map_err(|_| ErrorCode::InvalidRequest)?;
    if bytes.len() > 1_048_576 {
        return Err(ErrorCode::TooLarge);
    }
    let configuration: Configuration =
        serde_json::from_slice(&bytes).map_err(|_| ErrorCode::InvalidRequest)?;
    if configuration.maximum_lease_ms > configuration.storage_limits.ttl_ms
        || configuration.shutdown_ms == 0
        || configuration.registry.sweep_seconds == 0
    {
        return Err(ErrorCode::InvalidRequest);
    }
    let clock = WallClock::default();
    let network = match &configuration.storage {
        Storage::Memory => None,
        Storage::Valkey { url, timeout_ms } => {
            let timeout = Duration::from_millis(*timeout_ms);
            if timeout.is_zero() || timeout > Duration::from_secs(60) {
                return Err(ErrorCode::InvalidRequest);
            }
            runtime::valkey::check_url(url)?;
            let client =
                redis::Client::open(url.as_str()).map_err(|_| ErrorCode::InvalidRequest)?;
            let connection =
                tokio::time::timeout(timeout, client.get_multiplexed_async_connection())
                    .await
                    .map_err(|_| ErrorCode::AuthorityUnavailable)?
                    .map_err(|_| ErrorCode::AuthorityUnavailable)?;
            let network = Arc::new(
                cvtl::RedisNetwork::new(connection.clone(), timeout)
                    .map_err(|_| ErrorCode::InvalidRequest)?,
            );
            Some((network, connection))
        }
    };
    #[cfg(feature = "ohttp")]
    let gateway = match &configuration.ohttp {
        Some(settings) => Some(ohttp::build(settings, &configuration.storage).await?),
        None => None,
    };
    let limits = http::Limits {
        hosts: Vec::new(),
        origins: Vec::new(),
        body_bytes: configuration.request_bytes,
        concurrent: configuration.http_concurrent,
        anonymous_concurrent: configuration.http_anonymous_concurrent,
        body_timeout: Duration::from_millis(configuration.http_body_timeout_ms),
        request_timeout: Duration::from_millis(configuration.http_request_timeout_ms),
        source: configuration.source_bucket.bucket(),
        session: configuration.session_bucket.bucket(),
    };
    let bind = configuration.bind;
    let shutdown = Duration::from_millis(configuration.shutdown_ms);
    let sweep = Duration::from_secs(configuration.registry.sweep_seconds);
    let recheck = Duration::from_secs(configuration.registry.recheck_seconds);
    let maximum = configuration.registry.maximum_communities;
    let directory = Arc::new(registry::Http::new(&configuration.registry)?);
    let tenants = Arc::new(tenant::Tenants::new(
        directory,
        Arc::new(Platform(Arc::new(Shared {
            artifacts: configuration.accounting.artifacts()?,
            network,
            clock,
            configuration,
        }))),
        recheck,
        shutdown,
        maximum,
    )?);
    let app = http::router_tenants(limits, tenants.clone())?;
    #[cfg(feature = "ohttp")]
    let app = match gateway {
        Some(gateway) => cblv::gateway::mount(app, gateway),
        None => app,
    };
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|_| ErrorCode::Transport)?;
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .into_future();
    // The registry names finished communities; each is stopped and its stored
    // state deleted. A failed sweep is retried on the next tick.
    let sweeper = {
        let tenants = tenants.clone();
        async move {
            let mut interval = tokio::time::interval(sweep);
            loop {
                interval.tick().await;
                let _ = tenants.sweep().await;
            }
        }
    };
    let outcome = tokio::select! {
        result = server => result.map_err(|_| ErrorCode::Transport),
        () = sweeper => Ok(()),
        result = shutdown_signal() => result,
    };
    // Ingress is gone: drain admitted work in every community, then fence.
    tenants.stop_all().await;
    outcome
}

/// Starts a community's owner on shared inputs and deletes its stored state.
struct Platform(Arc<Shared>);
impl tenant::Backend for Platform {
    fn launch(
        &self,
        record: &tenant::Record,
    ) -> tenant::Fut<'_, Result<tenant::Launched, ErrorCode>> {
        let record = record.clone();
        Box::pin(async move { self.0.launch(&record).await })
    }
    fn purge(&self, id: &str) -> tenant::Fut<'_, Result<(), ErrorCode>> {
        let id = id.to_owned();
        Box::pin(async move { self.0.purge(&id).await })
    }
}

impl Shared {
    /// All state of one community lives under its registry identifier: storage
    /// scope, throttle and trust. Nothing is shared between communities.
    async fn launch(&self, record: &tenant::Record) -> Result<tenant::Launched, ErrorCode> {
        let c = &self.configuration;
        let scope =
            cmmr::Scope::new(&record.id, &c.incarnation).map_err(|_| ErrorCode::InvalidRequest)?;
        let storage: cvtl::Volatile<_> = match &self.network {
            None => cvtl::Volatile::memory(scope, c.storage_limits, self.clock.clone())
                .map_err(|_| ErrorCode::AuthorityUnavailable)?,
            Some((network, _)) => {
                cvtl::Volatile::valkey(network.clone(), scope, c.storage_limits, self.clock.clone())
                    .await
                    .map_err(|_| ErrorCode::AuthorityUnavailable)?
            }
        };
        // Persistent state is refused; an unreadable setting is only reported.
        runtime::valkey::check_persistence(storage.warnings())?;
        if !storage.warnings().is_empty() {
            eprintln!("forum volatile storage persistence could not be verified");
        }
        match &storage {
            cvtl::Volatile::Memory(_) => {
                let throttle = cthl::MemoryStore::new(c.throttle_capacity);
                self.start(record, storage, throttle).await
            }
            cvtl::Volatile::Valkey(backend) => {
                let throttle = cvtl::ThrottleStore::new(backend.clone(), c.throttle_capacity)
                    .map_err(|_| ErrorCode::InvalidRequest)?;
                self.start(record, storage, throttle).await
            }
        }
    }

    async fn start<Q: cthl::Store + 'static>(
        &self,
        record: &tenant::Record,
        storage: cvtl::Volatile<WallClock>,
        quota: Q,
    ) -> Result<tenant::Launched, ErrorCode> {
        let c = &self.configuration;
        // The registry alone supplies what this community's feed must be signed by.
        let trust = csrn::cchr::Configuration {
            origin: record.trust_origin.clone(),
            community: record.id.clone(),
            key_ring: record.key_ring.clone(),
            minimum_revision: record.minimum_revision,
            ring_revision: record.ring_revision,
        };
        let transport = csrn::http::Http::with_roots(&trust, &c.trust_roots_der)
            .map_err(|_| ErrorCode::InvalidRequest)?;
        let assurance = csrn::Assurance::new(
            trust,
            csrn::feed::Config {
                retry_entropy: entropy()?,
                refresh_seconds: c.refresh_seconds,
                poll_seconds: c.poll_seconds,
                request_seconds: c.request_seconds,
                initial_backoff_seconds: c.initial_backoff_seconds,
                maximum_backoff_seconds: c.maximum_backoff_seconds,
                maximum_staleness_seconds: c.maximum_staleness_seconds,
            },
        )
        .map_err(|_| ErrorCode::InvalidRequest)?;
        let mut rates = BTreeMap::new();
        for action in cfrm::actions() {
            let value = c
                .throttle
                .get(action.name)
                .ok_or(ErrorCode::InvalidRequest)?;
            let limit = cthl::Limit::new(value.burst, Duration::from_millis(value.replenish_ms))
                .map_err(|_| ErrorCode::InvalidRequest)?;
            rates.insert(action.name, limit);
        }
        if rates.len() != c.throttle.len() {
            return Err(ErrorCode::InvalidRequest);
        }
        let throttle =
            cthl::Throttle::new(&record.id, rates, quota).map_err(|_| ErrorCode::InvalidRequest)?;
        let native = c.accounting.verifier(&self.artifacts)?;
        let cancellation = native.cancellation();
        let record_limits = c.accounting.limits();
        let record_configuration = cgth::accounting::Configuration {
            community: record.id.clone(),
            period_key: c.accounting.period_key.clone(),
            period_seconds: c.accounting.period_seconds,
        };
        let service = runtime::Service::new(
            assurance,
            runtime::Parts {
                storage,
                clock: self.clock.clone(),
                tokens: Random,
                throttle,
            },
            runtime::Configuration {
                community: record.id.clone(),
                incarnation: c.incarnation.clone(),
                admission_action: c.admission_action.clone(),
                origins: record.origins.clone(),
                maximum_snapshot_age: c.maximum_snapshot_age,
                request_bytes: c.request_bytes,
                presence: cswb::Limits {
                    lease_ms: c.maximum_lease_ms,
                    publication_bytes: c.publication_bytes,
                    ciphertext_bytes: c.ciphertext_bytes,
                },
                lookup: clkp::LookupLimits {
                    candidates: c.candidate_count,
                    publication_bytes: c.page_publication_bytes,
                },
                room_epoch: c.room_epoch,
                rooms: cmbl::Limits {
                    connections: c.room_connections,
                    relay_messages: c.room_relay_messages,
                    message_bytes: c.room_message_bytes,
                    lifetime_ms: c.room_lifetime_ms,
                    proof_bytes: c.room_proof_bytes,
                    operation_receipts: c.room_operation_receipts,
                },
            },
            // No accepting detector is substituted: restricted public text stays
            // refused until an original contact detector can be supplied.
            |_: &str| cshm::ContactCheck::Unavailable,
        )?;
        let service = service.with_accounting(record_configuration, native, record_limits)?;
        let (handle, worker) =
            service.spawn(c.command_capacity, Duration::from_millis(c.maintenance_ms))?;
        let follower = tokio::spawn({
            let (handle, clock) = (handle.clone(), self.clock.clone());
            async move {
                let _ = follow(handle, transport, clock).await;
            }
        });
        Ok(tenant::Launched {
            handle,
            worker,
            follower,
            cancel: Box::new(move || cancellation.cancel()),
        })
    }

    /// Delete every key the community ever wrote (all incarnations). Memory
    /// storage lives inside the stopped owner and needs nothing.
    async fn purge(&self, id: &str) -> Result<(), ErrorCode> {
        let (Some((_, connection)), Storage::Valkey { timeout_ms, .. }) =
            (&self.network, &self.configuration.storage)
        else {
            return Ok(());
        };
        let pattern = purge_pattern(id);
        let mut connection = connection.clone();
        let work = async {
            let mut cursor = 0_u64;
            loop {
                let (next, keys): (u64, Vec<Vec<u8>>) = redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(&pattern)
                    .arg("COUNT")
                    .arg(500)
                    .query_async(&mut connection)
                    .await?;
                if !keys.is_empty() {
                    let mut command = redis::cmd("UNLINK");
                    for key in &keys {
                        command.arg(key.as_slice());
                    }
                    command.query_async::<()>(&mut connection).await?;
                }
                if next == 0 {
                    return Ok::<(), redis::RedisError>(());
                }
                cursor = next;
            }
        };
        tokio::time::timeout(Duration::from_millis(*timeout_ms) * 20, work)
            .await
            .map_err(|_| ErrorCode::AuthorityUnavailable)?
            .map_err(|_| ErrorCode::AuthorityUnavailable)
    }
}

/// The scope prefix cvlk gives every key of a community: `cvlk:v1:{community:incarnation}`.
fn purge_pattern(id: &str) -> String {
    format!("cvlk:v1:{{{id}:*")
}

async fn follow(
    handle: runtime::Handle,
    transport: csrn::http::Http,
    clock: WallClock,
) -> Result<(), ErrorCode> {
    let mut pending = Some(handle.start_feed().await?);
    loop {
        if let Some(request) = pending.take() {
            let now = clock.now().map_err(|_| ErrorCode::AuthorityUnavailable)? / 1000;
            let id = request.id();
            let announcement = matches!(request.action(), csrn::feed::Action::Poll { .. });
            match transport.execute(request, now).await {
                Ok(received) => {
                    let _ = handle
                        .complete_feed(id, received.bytes().to_vec(), announcement)
                        .await;
                }
                Err(_) => {
                    let _ = handle.failed_feed(id, entropy()?).await;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        pending = handle.next_feed().await?;
    }
}

async fn shutdown_signal() -> Result<(), ErrorCode> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| ErrorCode::AuthorityUnavailable)?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.map_err(|_| ErrorCode::AuthorityUnavailable),
        _ = term.recv() => Ok(()),
    }
}
