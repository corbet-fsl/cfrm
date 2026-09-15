//! Authenticated public presence and private introduction-allocation boundaries.
//! No profile content, messages, recipient IDs or relationship map belong here.

pub mod accounting;
#[cfg(feature = "sqlite")]
pub mod accounting_ledger;
mod accounting_policy;
pub mod admission;
#[cfg(feature = "sqlite")]
pub mod allocation;
pub mod board;
#[cfg(all(feature = "browser", target_arch = "wasm32"))]
pub mod browser;
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
