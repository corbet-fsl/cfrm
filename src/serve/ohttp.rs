//! Oblivious HTTP gateway wiring: keys from secret files, replay cache in Valkey.
use super::Storage;
use cblv::{
    gateway::{Gateway, GatewayKey, system_clock},
    replay::{BoxFuture, Id, Insert, ReplayStore, StoreError},
};
use cfrm::ErrorCode;
use serde::Deserialize;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use zeroize::Zeroizing;

const EPOCH_KEY: &str = "ohttp:forum:epoch";
const NONCE_PREFIX: &str = "ohttp:forum:n:";
const MAX_RESPONSE: usize = 1 << 20;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    /// The exact forum authority the gateway signs for. The gateway rewrites Host
    /// to it, so only the community that host resolves to is reachable through it.
    pub authority: String,
    pub keys: Vec<KeyFile>,
    /// File with the secret the Cloudflare proxy adds as `x-relay-auth`; absent only in tests.
    #[serde(default)]
    pub relay_secret_file: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyFile {
    pub key_id: u8,
    /// Raw secret input keying material (32 bytes or more); the public half is
    /// published in the signed trust feed.
    pub ikm_file: PathBuf,
    pub not_after: u64,
}

fn secret(path: &PathBuf) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
    std::fs::read(path)
        .map(Zeroizing::new)
        .map_err(|_| ErrorCode::InvalidRequest)
}

pub async fn build(settings: &Configuration, storage: &Storage) -> Result<Arc<Gateway>, ErrorCode> {
    if settings.authority.is_empty() || settings.keys.is_empty() || settings.keys.len() > 4 {
        return Err(ErrorCode::InvalidRequest);
    }
    // The replay cache must live in the shared store, never in process memory.
    let Storage::Valkey { url, timeout_ms } = storage else {
        return Err(ErrorCode::InvalidRequest);
    };
    let timeout = Duration::from_millis(*timeout_ms);
    let client = redis::Client::open(url.as_str()).map_err(|_| ErrorCode::InvalidRequest)?;
    let connection = tokio::time::timeout(timeout, client.get_multiplexed_async_connection())
        .await
        .map_err(|_| ErrorCode::AuthorityUnavailable)?
        .map_err(|_| ErrorCode::AuthorityUnavailable)?;
    let replay = ValkeyReplay::start(connection).await?;
    let mut keys = Vec::new();
    for file in &settings.keys {
        keys.push(
            GatewayKey::derive(file.key_id, &secret(&file.ikm_file)?, file.not_after)
                .map_err(|_| ErrorCode::InvalidRequest)?,
        );
    }
    Ok(Arc::new(Gateway {
        authority: settings.authority.clone(),
        keys,
        replay: Arc::new(replay),
        // Every forum call is cheap to record and most change state.
        mutating: Arc::new(|_| true),
        relay_secret: match &settings.relay_secret_file {
            Some(file) => Some(secret(file)?),
            None => None,
        },
        max_inner_response: MAX_RESPONSE,
        clock: system_clock,
    }))
}

struct ValkeyReplay {
    connection: redis::aio::MultiplexedConnection,
    started: AtomicU64,
}

impl ValkeyReplay {
    async fn start(mut connection: redis::aio::MultiplexedConnection) -> Result<Self, ErrorCode> {
        let now = system_clock();
        let unavailable = |_| ErrorCode::AuthorityUnavailable;
        let _: Option<String> = redis::cmd("SET")
            .arg(EPOCH_KEY)
            .arg(now)
            .arg("NX")
            .query_async(&mut connection)
            .await
            .map_err(unavailable)?;
        let epoch: Option<u64> = redis::cmd("GET")
            .arg(EPOCH_KEY)
            .query_async(&mut connection)
            .await
            .map_err(unavailable)?;
        Ok(Self {
            connection,
            started: AtomicU64::new(epoch.unwrap_or(now)),
        })
    }
}

fn hex(id: &Id) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl ReplayStore for ValkeyReplay {
    fn insert_if_absent(
        &self,
        id: Id,
        expires_at: u64,
    ) -> BoxFuture<'_, Result<Insert, StoreError>> {
        Box::pin(async move {
            let now = system_clock();
            let ttl = expires_at.saturating_sub(now).max(1);
            let mut connection = self.connection.clone();
            let (epoch, nonce): (Option<String>, Option<String>) = redis::pipe()
                .cmd("SET")
                .arg(EPOCH_KEY)
                .arg(now)
                .arg("NX")
                .cmd("SET")
                .arg(format!("{NONCE_PREFIX}{}", hex(&id)))
                .arg(1)
                .arg("NX")
                .arg("EX")
                .arg(ttl)
                .query_async(&mut connection)
                .await
                .map_err(|_| StoreError)?;
            if epoch.is_some() {
                // The epoch key was missing: the cache was flushed and forgot
                // earlier nonces. Refuse until the window has passed.
                self.started.store(now, Ordering::SeqCst);
                return Err(StoreError);
            }
            Ok(if nonce.is_some() {
                Insert::Fresh
            } else {
                Insert::Replayed
            })
        })
    }

    fn started_at(&self) -> u64 {
        self.started.load(Ordering::SeqCst)
    }
}
