//! One forum action registry and its transport projections.
//! Admission is closed until current child-owner capabilities are integrated.
#![forbid(unsafe_code)]
mod api;
mod client;
pub use api::*;
pub use client::*;
#[cfg(all(feature = "server", not(target_arch = "wasm32")))]
pub mod http;

#[cfg(test)]
mod portable_tests;
