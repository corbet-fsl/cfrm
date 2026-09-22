//! Small synchronous SQL boundary used by the durable service implementations.
//! SQL, policy checks and transaction order belong to those implementations.
use rusqlite::{
    types::{FromSql, ToSql, ToSqlOutput, Value, ValueRef},
    Error, Result, TransactionBehavior,
};
use std::{path::Path, time::Duration};

#[cfg(all(feature = "turso", not(target_arch = "wasm32")))]
mod remote;
#[cfg(all(feature = "turso", not(target_arch = "wasm32")))]
pub use remote::RemoteConfig;

pub(crate) trait Params {
    fn values(self) -> Result<Vec<Value>>;
}

fn value(input: &dyn ToSql) -> Result<Value> {
    match input.to_sql()? {
        ToSqlOutput::Borrowed(value) => {
            Value::column_result(value).map_err(|_| Error::InvalidQuery)
        }
        ToSqlOutput::Owned(value) => Ok(value),
        _ => Err(Error::InvalidQuery),
    }
}

impl Params for &[&dyn ToSql] {
    fn values(self) -> Result<Vec<Value>> {
        self.iter().map(|input| value(*input)).collect()
    }
}
impl Params for [(); 0] {
    fn values(self) -> Result<Vec<Value>> {
        Ok(Vec::new())
    }
}
macro_rules! array_params {
    ($($n:literal),+) => { $(
        impl<T: ToSql> Params for [T; $n] {
            fn values(self) -> Result<Vec<Value>> {
                self.iter().map(|input| value(input)).collect()
            }
        }
    )+ };
}
array_params!(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);

pub(crate) struct Row(Vec<Value>);
impl Row {
    pub(crate) fn get<I: TryInto<usize>, T: FromSql>(&self, index: I) -> Result<T> {
        let index = index.try_into().map_err(|_| Error::InvalidQuery)?;
        let value = self.0.get(index).ok_or(Error::InvalidColumnIndex(index))?;
        T::column_result(ValueRef::from(value)).map_err(|_| Error::InvalidQuery)
    }
}

pub(crate) struct Connection(Backend);
enum Backend {
    Local(rusqlite::Connection),
    #[cfg(all(feature = "turso", not(target_arch = "wasm32")))]
    Remote(remote::Remote),
}

impl Connection {
    pub(crate) fn open(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self(Backend::Local(rusqlite::Connection::open(path)?)))
    }

    #[cfg(all(feature = "turso", not(target_arch = "wasm32")))]
    pub(crate) fn open_remote(config: RemoteConfig) -> Result<Self> {
        Ok(Self(Backend::Remote(remote::Remote::open(config)?)))
    }

    pub(crate) fn configure_local(&self, timeout: Duration) -> Result<()> {
        match &self.0 {
            Backend::Local(connection) => {
                connection.busy_timeout(timeout)?;
                connection.execute_batch(
                    "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
                )
            }
            #[cfg(all(feature = "turso", not(target_arch = "wasm32")))]
            Backend::Remote(_) => Ok(()),
        }
    }

    pub(crate) fn execute_batch(&self, sql: &str) -> Result<()> {
        match &self.0 {
            Backend::Local(connection) => connection.execute_batch(sql),
            #[cfg(all(feature = "turso", not(target_arch = "wasm32")))]
            Backend::Remote(connection) => connection.batch(sql),
        }
    }

    pub(crate) fn query_row<T>(
        &self,
        sql: &str,
        params: impl Params,
        read: impl FnOnce(&Row) -> Result<T>,
    ) -> Result<T> {
        let params = params.values()?;
        match &self.0 {
            Backend::Local(connection) => {
                let row =
                    connection.query_row(sql, rusqlite::params_from_iter(params), copy_row)?;
                read(&row)
            }
            #[cfg(all(feature = "turso", not(target_arch = "wasm32")))]
            Backend::Remote(connection) => read(&connection.query(sql, params)?),
        }
    }

    pub(crate) fn transaction(&mut self) -> Result<Transaction<'_>> {
        self.transaction_with_behavior(TransactionBehavior::Deferred)
    }

    pub(crate) fn transaction_with_behavior(
        &mut self,
        behavior: TransactionBehavior,
    ) -> Result<Transaction<'_>> {
        let inner = match &mut self.0 {
            Backend::Local(connection) => {
                TransactionBackend::Local(connection.transaction_with_behavior(behavior)?)
            }
            #[cfg(all(feature = "turso", not(target_arch = "wasm32")))]
            Backend::Remote(connection) => {
                connection.begin(behavior)?;
                TransactionBackend::Remote(connection)
            }
        };
        Ok(Transaction { inner: Some(inner) })
    }
}

fn copy_row(row: &rusqlite::Row<'_>) -> Result<Row> {
    Ok(Row((0..row.as_ref().column_count())
        .map(|index| row.get(index))
        .collect::<Result<Vec<Value>>>()?))
}

pub(crate) struct Transaction<'a> {
    inner: Option<TransactionBackend<'a>>,
}
enum TransactionBackend<'a> {
    Local(rusqlite::Transaction<'a>),
    #[cfg(all(feature = "turso", not(target_arch = "wasm32")))]
    Remote(&'a remote::Remote),
}
impl Transaction<'_> {
    pub(crate) fn execute(&self, sql: &str, params: impl Params) -> Result<usize> {
        let params = params.values()?;
        match self.inner.as_ref().ok_or(Error::InvalidQuery)? {
            TransactionBackend::Local(transaction) => {
                transaction.execute(sql, rusqlite::params_from_iter(params))
            }
            #[cfg(all(feature = "turso", not(target_arch = "wasm32")))]
            TransactionBackend::Remote(connection) => connection.execute(sql, params),
        }
    }

    pub(crate) fn query_row<T>(
        &self,
        sql: &str,
        params: impl Params,
        read: impl FnOnce(&Row) -> Result<T>,
    ) -> Result<T> {
        let params = params.values()?;
        match self.inner.as_ref().ok_or(Error::InvalidQuery)? {
            TransactionBackend::Local(transaction) => {
                let row =
                    transaction.query_row(sql, rusqlite::params_from_iter(params), copy_row)?;
                read(&row)
            }
            #[cfg(all(feature = "turso", not(target_arch = "wasm32")))]
            TransactionBackend::Remote(connection) => read(&connection.query(sql, params)?),
        }
    }

    pub(crate) fn commit(mut self) -> Result<()> {
        match self.inner.take().ok_or(Error::InvalidQuery)? {
            TransactionBackend::Local(transaction) => transaction.commit(),
            #[cfg(all(feature = "turso", not(target_arch = "wasm32")))]
            TransactionBackend::Remote(connection) => connection.finish(true),
        }
    }

    pub(crate) fn rollback(mut self) -> Result<()> {
        match self.inner.take().ok_or(Error::InvalidQuery)? {
            TransactionBackend::Local(transaction) => transaction.rollback(),
            #[cfg(all(feature = "turso", not(target_arch = "wasm32")))]
            TransactionBackend::Remote(connection) => connection.finish(false),
        }
    }
}
impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        #[cfg(all(feature = "turso", not(target_arch = "wasm32")))]
        if let Some(TransactionBackend::Remote(connection)) = self.inner.take() {
            // A failed rollback poisons the remote connection. Drop never
            // claims that an uncertain COMMIT has been undone.
            let _ = connection.finish(false);
        }
    }
}
