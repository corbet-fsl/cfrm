use super::{Error, Result, Row, Value};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
        Arc,
    },
    time::Duration,
};

/// Explicit operator-owned endpoint and deadline. Tokens are never formatted.
/// HTTPS/libsql are required except for a loopback HTTP contract fixture.
pub struct RemoteConfig {
    pub url: String,
    pub auth_token: String,
    pub timeout: Duration,
}

pub(super) struct Remote {
    sender: SyncSender<Job>,
    poisoned: Arc<AtomicBool>,
    timeout: Duration,
}
struct Job {
    command: Command,
    reply: SyncSender<Result<Reply>>,
}
enum Command {
    Begin(libsql::TransactionBehavior),
    Batch(String),
    Execute(String, Vec<Value>),
    Query(String, Vec<Value>),
    Finish(bool),
}
enum Reply {
    Unit,
    Count(usize),
    Row(Option<Row>),
}

impl Remote {
    pub(super) fn open(config: RemoteConfig) -> Result<Self> {
        let url = url::Url::parse(&config.url).map_err(|_| Error::InvalidQuery)?;
        let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
        if !matches!(url.scheme(), "https" | "libsql") && !(url.scheme() == "http" && loopback)
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || config.auth_token.is_empty()
            || config.auth_token.len() > 16384
            || config.timeout.is_zero()
            || config.timeout > Duration::from_secs(60)
        {
            return Err(Error::InvalidQuery);
        }
        let (sender, receive) = mpsc::sync_channel::<Job>(1);
        let (ready, opened) = mpsc::sync_channel(1);
        let poisoned = Arc::new(AtomicBool::new(false));
        let failed = poisoned.clone();
        let timeout = config.timeout;
        std::thread::Builder::new()
            .name("cfrm-turso".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(value) => value,
                    Err(_) => {
                        let _ = ready.send(Err(Error::InvalidQuery));
                        return;
                    }
                };
                let database = runtime.block_on(async {
                    tokio::time::timeout(
                        timeout,
                        libsql::Builder::new_remote(config.url, config.auth_token).build(),
                    )
                    .await
                });
                let connection = match database {
                    Ok(Ok(database)) => database.connect(),
                    _ => {
                        let _ = ready.send(Err(Error::InvalidQuery));
                        return;
                    }
                };
                let connection = match connection {
                    Ok(value) => value,
                    Err(_) => {
                        let _ = ready.send(Err(Error::InvalidQuery));
                        return;
                    }
                };
                if ready.send(Ok(())).is_err() {
                    return;
                }
                let mut transaction = None;
                while let Ok(job) = receive.recv() {
                    if failed.load(Ordering::Acquire) {
                        break;
                    }
                    let result = runtime.block_on(async {
                        tokio::time::timeout(
                            timeout,
                            perform(&connection, &mut transaction, job.command),
                        )
                        .await
                    });
                    let result = match result {
                        Ok(value) => value,
                        Err(_) => Err(Error::InvalidQuery),
                    };
                    if result.is_err() {
                        failed.store(true, Ordering::Release);
                    }
                    let _ = job.reply.send(result);
                    if failed.load(Ordering::Acquire) {
                        break;
                    }
                }
                // Best effort only. Timeout/transport failure is uncertain and
                // the retired connection can never authorize another action.
                runtime.block_on(async {
                    if let Some(transaction) = transaction.take() {
                        let _ = tokio::time::timeout(timeout, transaction.rollback()).await;
                    }
                });
            })
            .map_err(|_| Error::InvalidQuery)?;
        opened
            .recv_timeout(timeout + Duration::from_secs(1))
            .map_err(|_| Error::InvalidQuery)??;
        Ok(Self {
            sender,
            poisoned,
            timeout,
        })
    }

    fn request(&self, command: Command) -> Result<Reply> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(Error::InvalidQuery);
        }
        let (reply, receive) = mpsc::sync_channel(1);
        let result = self
            .sender
            .try_send(Job { command, reply })
            .map_err(|_| Error::InvalidQuery)
            .and_then(|()| {
                receive
                    .recv_timeout(self.timeout + Duration::from_secs(1))
                    .map_err(|_| Error::InvalidQuery)
            })
            .and_then(|value| value);
        if result.is_err() {
            self.poisoned.store(true, Ordering::Release);
        }
        result
    }
    pub(super) fn begin(&self, behavior: rusqlite::TransactionBehavior) -> Result<()> {
        let behavior = match behavior {
            rusqlite::TransactionBehavior::Deferred => libsql::TransactionBehavior::Deferred,
            rusqlite::TransactionBehavior::Immediate => libsql::TransactionBehavior::Immediate,
            _ => return Err(Error::InvalidQuery),
        };
        match self.request(Command::Begin(behavior))? {
            Reply::Unit => Ok(()),
            _ => Err(Error::InvalidQuery),
        }
    }
    pub(super) fn batch(&self, sql: &str) -> Result<()> {
        match self.request(Command::Batch(sql.into()))? {
            Reply::Unit => Ok(()),
            _ => Err(Error::InvalidQuery),
        }
    }
    pub(super) fn execute(&self, sql: &str, params: Vec<Value>) -> Result<usize> {
        match self.request(Command::Execute(sql.into(), params))? {
            Reply::Count(value) => Ok(value),
            _ => Err(Error::InvalidQuery),
        }
    }
    pub(super) fn query(&self, sql: &str, params: Vec<Value>) -> Result<Row> {
        match self.request(Command::Query(sql.into(), params))? {
            Reply::Row(Some(value)) => Ok(value),
            Reply::Row(None) => Err(Error::QueryReturnedNoRows),
            _ => Err(Error::InvalidQuery),
        }
    }
    pub(super) fn finish(&self, commit: bool) -> Result<()> {
        match self.request(Command::Finish(commit))? {
            Reply::Unit => Ok(()),
            _ => Err(Error::InvalidQuery),
        }
    }
}

fn params(values: Vec<Value>) -> Vec<libsql::Value> {
    values
        .into_iter()
        .map(|value| match value {
            Value::Null => libsql::Value::Null,
            Value::Integer(value) => libsql::Value::Integer(value),
            Value::Real(value) => libsql::Value::Real(value),
            Value::Text(value) => libsql::Value::Text(value),
            Value::Blob(value) => libsql::Value::Blob(value),
        })
        .collect()
}
async fn perform(
    connection: &libsql::Connection,
    transaction: &mut Option<libsql::Transaction>,
    command: Command,
) -> Result<Reply> {
    let sql_error = |_| Error::InvalidQuery;
    match command {
        Command::Begin(behavior) => {
            if transaction.is_some() {
                return Err(Error::InvalidQuery);
            }
            *transaction = Some(
                connection
                    .transaction_with_behavior(behavior)
                    .await
                    .map_err(sql_error)?,
            );
            let active = transaction.as_ref().ok_or(Error::InvalidQuery)?;
            let mut rows = active
                .query("PRAGMA foreign_keys", ())
                .await
                .map_err(sql_error)?;
            let enabled = rows
                .next()
                .await
                .map_err(sql_error)?
                .ok_or(Error::InvalidQuery)?
                .get::<i64>(0)
                .map_err(sql_error)?;
            if enabled != 1 || rows.next().await.map_err(sql_error)?.is_some() {
                return Err(Error::InvalidQuery);
            }
            Ok(Reply::Unit)
        }
        Command::Finish(commit) => {
            let active = transaction.take().ok_or(Error::InvalidQuery)?;
            if commit {
                active.commit().await
            } else {
                active.rollback().await
            }
            .map_err(sql_error)?;
            Ok(Reply::Unit)
        }
        Command::Batch(sql) => {
            if transaction.is_some() {
                return Err(Error::InvalidQuery);
            }
            connection.execute_batch(&sql).await.map_err(sql_error)?;
            Ok(Reply::Unit)
        }
        Command::Execute(sql, values) => {
            let active = transaction.as_ref().ok_or(Error::InvalidQuery)?;
            let count = active
                .execute(&sql, params(values))
                .await
                .map_err(sql_error)?;
            Ok(Reply::Count(
                count.try_into().map_err(|_| Error::InvalidQuery)?,
            ))
        }
        Command::Query(sql, values) => {
            let active = transaction.as_deref().unwrap_or(connection);
            let mut rows = active
                .query(&sql, params(values))
                .await
                .map_err(sql_error)?;
            let Some(row) = rows.next().await.map_err(sql_error)? else {
                return Ok(Reply::Row(None));
            };
            let count = row.column_count();
            if !(0..=64).contains(&count) {
                return Err(Error::InvalidQuery);
            }
            let mut values = Vec::new();
            for index in 0..count {
                values.push(match row.get_value(index).map_err(sql_error)? {
                    libsql::Value::Null => Value::Null,
                    libsql::Value::Integer(value) => Value::Integer(value),
                    libsql::Value::Real(value) => Value::Real(value),
                    libsql::Value::Text(value) => Value::Text(value),
                    libsql::Value::Blob(value) => Value::Blob(value),
                });
            }
            // Finish the response while the transaction still owns its stream.
            // Every store query is a scalar or uniquely keyed single-row query.
            if rows.next().await.map_err(sql_error)?.is_some() {
                return Err(Error::InvalidQuery);
            }
            Ok(Reply::Row(Some(Row(values))))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Connection;
    use rusqlite::{params, TransactionBehavior};

    pub(crate) fn config() -> RemoteConfig {
        assert_eq!(std::env::var("CI").as_deref(), Ok("true"));
        let url = std::env::var("CFRM_TURSO_CONTRACT_URL").unwrap();
        assert!(url.starts_with("http://127.0.0.1:"));
        RemoteConfig {
            url,
            auth_token: "isolated-contract-only".into(),
            timeout: Duration::from_secs(5),
        }
    }

    #[test]
    #[ignore = "requires the isolated official sqld contract lane"]
    fn remote_transaction_contract() {
        let mut first = Connection::open_remote(config()).unwrap();
        first.execute_batch("CREATE TABLE adapter_contract (id INTEGER PRIMARY KEY, version INTEGER NOT NULL, payload BLOB NOT NULL, label TEXT NOT NULL);").unwrap();
        {
            let tx = first
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            tx.execute(
                "INSERT INTO adapter_contract VALUES(1,0,?1,?2)",
                params![vec![0_u8, 255, 17], "text☃"],
            )
            .unwrap();
            tx.commit().unwrap();
        }
        let row: (i64, Vec<u8>, String) = first
            .query_row(
                "SELECT version,payload,label FROM adapter_contract WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(row, (0, vec![0, 255, 17], "text☃".into()));
        {
            let tx = first
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            tx.execute("UPDATE adapter_contract SET version=8 WHERE id=1", [])
                .unwrap();
        }
        assert_eq!(
            first
                .query_row(
                    "SELECT version FROM adapter_contract WHERE id=1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let writers: Vec<_> = (0..2)
            .map(|_| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let mut connection = Connection::open_remote(config()).unwrap();
                    barrier.wait();
                    let tx = connection
                        .transaction_with_behavior(TransactionBehavior::Immediate)
                        .unwrap();
                    let changed = tx
                        .execute(
                            "UPDATE adapter_contract SET version=1 WHERE id=1 AND version=0",
                            [],
                        )
                        .unwrap();
                    tx.commit().unwrap();
                    changed
                })
            })
            .collect();
        assert_eq!(
            writers
                .into_iter()
                .map(|writer| writer.join().unwrap())
                .sum::<usize>(),
            1
        );
        let mut fault = config();
        fault.url = std::env::var("CFRM_TURSO_FAULT_URL").unwrap();
        assert!(fault.url.starts_with("http://127.0.0.1:"));
        fault.timeout = Duration::from_secs(1);
        let mut uncertain = Connection::open_remote(fault).unwrap();
        let tx = uncertain
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        tx.execute(
            "UPDATE adapter_contract SET version=2 WHERE id=1 AND version=1",
            [],
        )
        .unwrap();
        // The pass-through fixture discards the reply only after official sqld
        // has successfully executed this exact COMMIT.
        assert!(tx.commit().is_err());
        assert!(uncertain
            .query_row("SELECT version FROM adapter_contract", [], |row| row
                .get::<_, i64>(0))
            .is_err());
        let reopened = Connection::open_remote(config()).unwrap();
        assert_eq!(
            reopened
                .query_row(
                    "SELECT version FROM adapter_contract WHERE id=1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
    }
}
