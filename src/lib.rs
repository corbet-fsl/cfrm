//! Authenticated public presence and private introduction-allocation boundaries.
//! No profile content, messages, recipient IDs or relationship map belong here.

pub mod accounting;
#[cfg(feature = "sqlite")]
pub mod accounting_ledger;
mod accounting_policy;
#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
pub mod accounting_service;
pub mod admission;
#[cfg(feature = "sqlite")]
pub mod allocation;
pub mod board;
#[cfg(all(feature = "browser", target_arch = "wasm32"))]
pub mod browser;
pub mod discovery;
#[cfg(all(feature = "discovery-api", not(target_arch = "wasm32")))]
pub mod discovery_api;
#[cfg(feature = "sqlite")]
pub mod discovery_control;
pub mod discovery_store;
#[cfg(all(feature = "discovery-valkey", not(target_arch = "wasm32")))]
pub mod discovery_valkey;
#[cfg(feature = "permits")]
pub mod key_access;
#[cfg(all(feature = "permit-issuer", not(target_arch = "wasm32")))]
pub mod permit_issuer;
#[cfg(feature = "permits")]
pub mod permits;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    Admission,
    Signature,
    Expired,
    ClockRollback,
    Replay,
    Capacity,
    NoAllowance,
    PolicyMismatch,
    Storage,
    UnsupportedCapability,
    CryptoProvider,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}
