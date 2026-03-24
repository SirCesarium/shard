//! Shard SDK: High-performance, hardened binary transport over UDP.
//!
//! This crate provides the asynchronous implementation of the Shard protocol,
//! leveraging Tokio for non-blocking I/O and shard-core for cryptographic integrity.

#![deny(clippy::all, clippy::pedantic, missing_docs)]

pub mod client;
pub mod config;
pub mod server;
pub mod session;
pub mod util;

/// Foreign Function Interface (FFI) for C and Java (Project Panama).
pub mod ffi;

pub use crate::config::ShardConfig;
/// Re-exporting core errors for easier access.
pub use shard_core::ShardError;
