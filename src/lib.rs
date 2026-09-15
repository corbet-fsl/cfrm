//! Authenticated public presence and private introduction-allocation boundaries.
//! No profile content, messages, recipient IDs or relationship map belong here.

pub mod admission;
pub mod board;
#[cfg(feature = "sqlite")]
pub mod allocation;
#[cfg(feature = "permits")]
pub mod permits;
#[cfg(all(feature = "permit-issuer", not(target_arch = "wasm32")))]
pub mod permit_issuer;

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
