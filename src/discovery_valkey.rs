//! Pooled Valkey discovery storage. The service verifies signatures before this
//! adapter atomically commits per-member state and live-index changes.
use crate::{
    admission::{digest, scope},
    discovery::{
        CachedProfile, DiscoveryLimits, DiscoveryOperation, DiscoveryResponse, DiscoveryStore,
        VerifiedDiscoveryRequest,
    },
    discovery_control::SqliteDiscoveryControl,
    discovery_store::{summary, QueryPage},
    Error,
};
use redis::ConnectionLike;
use std::{sync::Arc, time::Duration};

/// Runtime credentials belong in the supplied URL, never logs or browser config.
pub struct ValkeyConfig {
    pub url: String,
    pub namespace: String,
    pub pool_size: u32,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub pool_timeout: Duration,
    /// Test-only loopback connections may omit TLS; remote connections may not.
    pub allow_plaintext_loopback: bool,
    pub root_certificate_pem: Option<Vec<u8>>,
}

struct Manager {
    client: redis::Client,
    connect_timeout: Duration,
    io_timeout: Duration,
}

impl r2d2::ManageConnection for Manager {
    type Connection = redis::Connection;
    type Error = redis::RedisError;
    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let connection = self
            .client
            .get_connection_with_timeout(self.connect_timeout)?;
        connection.set_read_timeout(Some(self.io_timeout))?;
        connection.set_write_timeout(Some(self.io_timeout))?;
        Ok(connection)
    }
    fn is_valid(&self, connection: &mut Self::Connection) -> Result<(), Self::Error> {
        redis::cmd("PING").query::<String>(connection).map(|_| ())
    }
    fn has_broken(&self, connection: &mut Self::Connection) -> bool {
        !connection.is_open()
    }
}

/// Every operation uses a bounded shared pool, not a connection per member.
pub struct ValkeyDiscoveryStore {
    pool: r2d2::Pool<Manager>,
    namespace: String,
    pool_timeout: Duration,
    control: Arc<SqliteDiscoveryControl>,
}

const COMMIT: &str = r#"
local member = ARGV[1]
local live = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local ttl = tonumber(ARGV[5])
if live > now then
  if ARGV[4] ~= '' then redis.call('SET', KEYS[1], ARGV[4], 'EX', live-now) end
  if redis.call('EXISTS', KEYS[1]) == 1 then
    redis.call('EXPIRE', KEYS[1], live-now)
    redis.call('ZADD', KEYS[2], 0, member)
    redis.call('ZADD', KEYS[3], live, member)
  else
    redis.call('ZREM', KEYS[2], member)
    redis.call('ZREM', KEYS[3], member)
  end
else
  redis.call('DEL', KEYS[1])
  redis.call('ZREM', KEYS[2], member)
  redis.call('ZREM', KEYS[3], member)
end
for _, i in ipairs({2,3}) do
  if redis.call('TTL', KEYS[i]) < ttl then redis.call('EXPIRE', KEYS[i], ttl) end
end
return 1
"#;

// Reads never attach reader identities to target keys or index observations.
const FETCH: &str = r#"
local until_at = tonumber(redis.call('ZSCORE', KEYS[2], ARGV[1]) or '0')
if until_at <= tonumber(ARGV[2]) then return nil end
return redis.call('GET', KEYS[1])
"#;

impl ValkeyDiscoveryStore {
    pub fn connect(
        config: ValkeyConfig,
        control: Arc<SqliteDiscoveryControl>,
    ) -> Result<Self, Error> {
        // redis disables rustls' default features and uses ClientConfig::builder.
        // Select the enabled provider explicitly, while respecting an embedding
        // that already installed another reviewed process-wide provider.
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        if !scope(&config.namespace)
            || config.pool_size == 0
            || config.pool_size > 1024
            || config.connect_timeout.is_zero()
            || config.io_timeout.is_zero()
            || config.pool_timeout.is_zero()
        {
            return Err(Error::InvalidInput);
        }
        let info = redis::Client::open(config.url.as_str()).map_err(|_| Error::Storage)?;
        match info.get_connection_info().addr() {
            redis::ConnectionAddr::TcpTls {
                insecure: false, ..
            } => (),
            redis::ConnectionAddr::Tcp(host, _)
                if config.allow_plaintext_loopback
                    && matches!(host.as_str(), "127.0.0.1" | "::1") =>
            {
                ()
            }
            _ => return Err(Error::InvalidInput),
        }
        let client = if config.root_certificate_pem.is_some() {
            redis::Client::build_with_tls(
                config.url.as_str(),
                redis::TlsCertificates {
                    client_tls: None,
                    root_cert: config.root_certificate_pem,
                },
            )
            .map_err(|_| Error::Storage)?
        } else {
            info
        };
        let manager = Manager {
            client,
            connect_timeout: config.connect_timeout,
            io_timeout: config.io_timeout,
        };
        let pool = r2d2::Pool::builder()
            .max_size(config.pool_size)
            .min_idle(Some(0))
            .connection_timeout(config.pool_timeout)
            .build(manager)
            .map_err(|_| Error::Storage)?;
        Ok(Self {
            pool,
            namespace: config.namespace,
            pool_timeout: config.pool_timeout,
            control,
        })
    }

    fn prefix(&self, community: &str) -> String {
        format!(
            "cfrm:{{{}}}",
            digest(format!("{}\0{}", self.namespace, community).as_bytes())
        )
    }

    fn fetch(
        &self,
        connection: &mut redis::Connection,
        prefix: &str,
        community: &str,
        member: &str,
        now: u64,
    ) -> Result<Option<(CachedProfile, u64)>, Error> {
        let body: Option<String> = redis::Script::new(FETCH)
            .key(format!("{prefix}:profile:{member}"))
            .key(format!("{prefix}:live"))
            .arg(member)
            .arg(now)
            .invoke(connection)
            .map_err(|_| Error::Storage)?;
        let Some(body) = body else {
            return Ok(None);
        };
        let publication: CachedProfile = serde_json::from_str(&body).map_err(|_| Error::Storage)?;
        let Some(state) = self.control.current(community, member, now)? else {
            return Ok(None);
        };
        let hash = digest(&serde_json::to_vec(&publication).map_err(|_| Error::Storage)?);
        let until = state.live_until(now);
        if state.publication_hash != hash || until <= now {
            return Ok(None);
        }
        Ok(Some((publication, until)))
    }
}

impl DiscoveryStore for ValkeyDiscoveryStore {
    fn execute(
        &self,
        request: &VerifiedDiscoveryRequest,
        limits: &DiscoveryLimits,
        now: u64,
    ) -> Result<DiscoveryResponse, Error> {
        let mut connection = self
            .pool
            .get_timeout(self.pool_timeout)
            .map_err(|_| Error::Capacity)?;
        let prefix = self.prefix(&request.community_id);
        let profile_key = format!("{prefix}:profile:{}", request.member_id);
        let catalog_key = format!("{prefix}:catalog");
        let live_key = format!("{prefix}:live");
        // Commit guards before cache I/O. An error can consume a resource quota,
        // but exact signed write retries recover without charging it again.
        let commit = self.control.authorize(request, limits, now)?;
        if !matches!(
            request.operation,
            DiscoveryOperation::Query { .. } | DiscoveryOperation::Fetch { .. }
        ) {
            self.control.with_current(&commit, |state| {
                let body = commit
                    .publication
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()
                    .map_err(|_| Error::InvalidInput)?
                    .unwrap_or_default();
                let result: i32 = redis::Script::new(COMMIT)
                    .key(&profile_key)
                    .key(&catalog_key)
                    .key(&live_key)
                    .arg(&request.member_id)
                    .arg(state.live_until(now))
                    .arg(now)
                    .arg(body)
                    .arg(state.retain_until.saturating_sub(now).max(1))
                    .invoke(&mut *connection)
                    .map_err(|_| Error::Storage)?;
                if result != 1 {
                    return Err(Error::Storage);
                }
                Ok(())
            })?;
        }
        match &request.operation {
            DiscoveryOperation::Fetch { member_id } => Ok(DiscoveryResponse::Profile {
                publication: self
                    .fetch(
                        &mut connection,
                        &prefix,
                        &request.community_id,
                        member_id,
                        now,
                    )?
                    .map(|(value, _)| value),
            }),
            DiscoveryOperation::Query {
                filters,
                limit,
                after,
            } => {
                let lower = after
                    .as_ref()
                    .map(|cursor| format!("({cursor}"))
                    .unwrap_or_else(|| "-".into());
                let candidates: Vec<String> = redis::cmd("ZRANGEBYLEX")
                    .arg(&catalog_key)
                    .arg(lower)
                    .arg("+")
                    .arg("LIMIT")
                    .arg(0)
                    .arg(limits.max_scan + 1)
                    .query(&mut *connection)
                    .map_err(|_| Error::Storage)?;
                let mut page = QueryPage::new(limits.max_response_bytes)?;
                let mut scanned = 0;
                let mut more = false;
                for member in candidates {
                    if scanned >= limits.max_scan || page.len() >= *limit {
                        more = true;
                        break;
                    }
                    let mut entry = None;
                    if let Some((publication, until)) = self.fetch(
                        &mut connection,
                        &prefix,
                        &request.community_id,
                        &member,
                        now,
                    )? {
                        if filters.iter().all(|(key, value)| {
                            publication.envelope.discriminators.get(key) == Some(value)
                        }) {
                            entry = Some(summary(&publication, until));
                        }
                    } else {
                        // Only delete an index row if it is still expired atomically.
                        let _: i32 = redis::Script::new("local v=tonumber(redis.call('ZSCORE',KEYS[2],ARGV[1]) or '0'); if v<=tonumber(ARGV[2]) or redis.call('EXISTS',KEYS[3])==0 then redis.call('ZREM',KEYS[1],ARGV[1]); redis.call('ZREM',KEYS[2],ARGV[1]); end; return 1")
                            .key(&catalog_key).key(&live_key).key(format!("{prefix}:profile:{member}"))
                            .arg(&member).arg(now).invoke(&mut *connection).map_err(|_| Error::Storage)?;
                    }
                    if !page.consider(&member, entry)? {
                        more = true;
                        break;
                    }
                    scanned += 1;
                }
                Ok(page.finish(more))
            }
            _ => Ok(DiscoveryResponse::Updated),
        }
    }
}
