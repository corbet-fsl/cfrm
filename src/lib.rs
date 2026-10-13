//! One forum action registry and its transport projections.
//! Admission is closed until current child-owner capabilities are integrated.
#![forbid(unsafe_code)]
mod api;
mod client;
pub use api::*;
pub use client::*;
#[cfg(all(feature = "server", not(target_arch = "wasm32")))]
pub mod bucket;
#[cfg(all(feature = "server", not(target_arch = "wasm32")))]
pub mod http;

#[cfg(test)]
mod portable_tests;

#[cfg(all(feature = "server", not(target_arch = "wasm32")))]
pub mod runtime;
#[cfg(all(feature = "server", not(target_arch = "wasm32")))]
pub mod tenant;

#[cfg(all(feature = "client-http", not(target_arch = "wasm32")))]
mod client_http;
#[cfg(feature = "client-ohttp")]
mod client_ohttp;
#[cfg(any(
    all(feature = "client-http", not(target_arch = "wasm32")),
    all(feature = "client-browser", target_arch = "wasm32"),
    feature = "client-ohttp"
))]
mod endpoint;
#[cfg(all(feature = "client-http", not(target_arch = "wasm32")))]
pub use client_http::HttpTransport;
#[cfg(feature = "client-ohttp")]
pub use client_ohttp::OhttpTransport;
#[cfg(all(feature = "client-browser", target_arch = "wasm32"))]
mod client_browser;
#[cfg(all(feature = "client-browser", target_arch = "wasm32"))]
pub use client_browser::BrowserTransport;

/// Original settings projection and maintained client-version decision.
pub use crbk;
