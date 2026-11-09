//! The crate's integration tests in one binary.
//!
//! Every former `tests/<name>.rs` is a module here, so a warm edit loop links one test
//! executable instead of one per file. The test names keep their module prefix
//! (`<name>::<test>`). `native_record` keeps its inner `#![cfg(all(feature = "server",
//! target_os = "linux"))]` and its `native_record/` support modules move with it.
mod created_community;
mod mcp_projection;
mod native_record;
mod owner_scenarios;
mod runtime;
mod support;
