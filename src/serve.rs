use cfrm::{ErrorCode, http, runtime};
use cgth::{clkp, cmbl, cmmr, cswb, cthl};
use cmmr::{Clock, Store};
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
    community: String,
    admission_action: String,
    accounting: accounting::Configuration,
    incarnation: String,
    hosts: Vec<String>,
    origins: Vec<String>,
    trust_origin: String,
    trust_key_ring: Vec<u8>,
    trust_minimum_revision: u64,
    trust_ring_revision: u64,
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
    http_body_timeout_ms: u64,
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
    {
        return Err(ErrorCode::InvalidRequest);
    }
    let clock = WallClock::default();
    let scope = cmmr::Scope::new(&configuration.community, &configuration.incarnation)
        .map_err(|_| ErrorCode::InvalidRequest)?;
    let storage: cvtl::Volatile<_> = match &configuration.storage {
        Storage::Memory => {
            cvtl::Volatile::memory(scope, configuration.storage_limits, clock.clone())
                .map_err(|_| ErrorCode::AuthorityUnavailable)?
        }
        Storage::Valkey { url, timeout_ms } => {
            let timeout = Duration::from_millis(*timeout_ms);
            if timeout.is_zero() || timeout > Duration::from_secs(60) {
                return Err(ErrorCode::InvalidRequest);
            }
            let client =
                redis::Client::open(url.as_str()).map_err(|_| ErrorCode::InvalidRequest)?;
            let connection =
                tokio::time::timeout(timeout, client.get_multiplexed_async_connection())
                    .await
                    .map_err(|_| ErrorCode::AuthorityUnavailable)?
                    .map_err(|_| ErrorCode::AuthorityUnavailable)?;
            let network = Arc::new(
                cvtl::RedisNetwork::new(connection, timeout)
                    .map_err(|_| ErrorCode::InvalidRequest)?,
            );
            cvtl::Volatile::valkey(network, scope, configuration.storage_limits, clock.clone())
                .await
                .map_err(|_| ErrorCode::AuthorityUnavailable)?
        }
    };
    if !storage.warnings().is_empty() {
        eprintln!("forum volatile storage persistence is enabled or unknown");
    }
    match &storage {
        cvtl::Volatile::Memory(_) => {
            let throttle = cthl::MemoryStore::new(configuration.throttle_capacity);
            serve(configuration, storage, clock, throttle).await
        }
        cvtl::Volatile::Valkey(backend) => {
            let throttle =
                cvtl::ThrottleStore::new(backend.clone(), configuration.throttle_capacity)
                    .map_err(|_| ErrorCode::InvalidRequest)?;
            serve(configuration, storage, clock, throttle).await
        }
    }
}

async fn serve<Q: cthl::Store + 'static>(
    configuration: Configuration,
    storage: cvtl::Volatile<WallClock>,
    clock: WallClock,
    quota: Q,
) -> Result<(), ErrorCode> {
    let trust = csrn::cchr::Configuration {
        origin: configuration.trust_origin,
        community: configuration.community.clone(),
        key_ring: configuration.trust_key_ring,
        minimum_revision: configuration.trust_minimum_revision,
        ring_revision: configuration.trust_ring_revision,
    };
    let transport = csrn::http::Http::with_roots(&trust, &configuration.trust_roots_der)
        .map_err(|_| ErrorCode::InvalidRequest)?;
    let assurance = csrn::Assurance::new(
        trust,
        csrn::feed::Config {
            retry_entropy: entropy()?,
            refresh_seconds: configuration.refresh_seconds,
            poll_seconds: configuration.poll_seconds,
            request_seconds: configuration.request_seconds,
            initial_backoff_seconds: configuration.initial_backoff_seconds,
            maximum_backoff_seconds: configuration.maximum_backoff_seconds,
            maximum_staleness_seconds: configuration.maximum_staleness_seconds,
        },
    )
    .map_err(|_| ErrorCode::InvalidRequest)?;
    let mut rates = BTreeMap::new();
    for action in cfrm::actions() {
        let value = configuration
            .throttle
            .get(action.name)
            .ok_or(ErrorCode::InvalidRequest)?;
        let limit = cthl::Limit::new(value.burst, Duration::from_millis(value.replenish_ms))
            .map_err(|_| ErrorCode::InvalidRequest)?;
        rates.insert(action.name, limit);
    }
    if rates.len() != configuration.throttle.len() {
        return Err(ErrorCode::InvalidRequest);
    }
    let throttle = cthl::Throttle::new(&configuration.community, rates, quota)
        .map_err(|_| ErrorCode::InvalidRequest)?;
    let native = configuration.accounting.verifier()?;
    let cancellation = native.cancellation();
    let record_limits = configuration.accounting.limits();
    let record_configuration = cgth::accounting::Configuration {
        community: configuration.community.clone(),
        period_key: configuration.accounting.period_key,
        period_seconds: configuration.accounting.period_seconds,
    };
    let service = runtime::Service::new(
        assurance,
        runtime::Parts {
            storage: storage.clone(),
            clock: clock.clone(),
            tokens: Random,
            throttle,
        },
        runtime::Configuration {
            community: configuration.community,
            incarnation: configuration.incarnation,
            admission_action: configuration.admission_action,
            origins: configuration.origins.clone(),
            maximum_snapshot_age: configuration.maximum_snapshot_age,
            request_bytes: configuration.request_bytes,
            presence: cswb::Limits {
                lease_ms: configuration.maximum_lease_ms,
                publication_bytes: configuration.publication_bytes,
                ciphertext_bytes: configuration.ciphertext_bytes,
            },
            lookup: clkp::LookupLimits {
                candidates: configuration.candidate_count,
                publication_bytes: configuration.page_publication_bytes,
            },
            room_epoch: configuration.room_epoch,
            rooms: cmbl::Limits {
                connections: configuration.room_connections,
                relay_messages: configuration.room_relay_messages,
                message_bytes: configuration.room_message_bytes,
                lifetime_ms: configuration.room_lifetime_ms,
                proof_bytes: configuration.room_proof_bytes,
                operation_receipts: configuration.room_operation_receipts,
            },
        },
        |_: &str| cshm::ContactCheck::Unavailable,
    )?;
    let service = service.with_accounting(record_configuration, native, record_limits)?;
    // No accepting detector is substituted: restricted public text stays refused
    // until an original contact detector can be supplied by the service owner.
    let (handle, mut worker) = service.spawn(
        configuration.command_capacity,
        Duration::from_millis(configuration.maintenance_ms),
    )?;
    let app = http::router_with(
        http::Limits {
            hosts: configuration.hosts,
            origins: configuration.origins,
            body_bytes: configuration.request_bytes,
            concurrent: configuration.http_concurrent,
            body_timeout: Duration::from_millis(configuration.http_body_timeout_ms),
        },
        handle.clone(),
    )?;
    let listener = tokio::net::TcpListener::bind(configuration.bind)
        .await
        .map_err(|_| ErrorCode::Transport)?;
    let (outcome, finished) = {
        let feed = follow(handle.clone(), transport, clock);
        let server = axum::serve(listener, app).into_future();
        tokio::pin!(feed, server);
        tokio::select! {
            result = &mut worker => { let _ = result; (Err(ErrorCode::AuthorityUnavailable), true) },
            result = &mut feed => (result, false),
            result = &mut server => (result.map_err(|_| ErrorCode::Transport), false),
            result = shutdown() => (result, false),
        }
    };
    // Dropping the network futures stops ingress. Drain commands already admitted
    // to the bounded owner queue; timeout/panic fences every storage clone.
    drop(handle);
    if !finished {
        match tokio::time::timeout(
            Duration::from_millis(configuration.shutdown_ms),
            &mut worker,
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                storage.close();
                return Err(ErrorCode::AuthorityUnavailable);
            }
            Err(_) => {
                storage.close();
                // Tokio abort cannot preempt synchronous native polling. Revoke
                // its actual process owner first; it kills/reaps before yielding.
                cancellation.cancel();
                worker.abort();
                let _ = worker.await;
                return Err(ErrorCode::AuthorityUnavailable);
            }
        }
    }
    storage.close();
    outcome
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

async fn shutdown() -> Result<(), ErrorCode> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| ErrorCode::AuthorityUnavailable)?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.map_err(|_| ErrorCode::AuthorityUnavailable),
        _ = term.recv() => Ok(()),
    }
}
