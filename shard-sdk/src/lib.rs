//! # Shard SDK
//!
//! High-level asynchronous toolkit for the Shard 2.0 Protocol.
//!
//! This crate provides a robust, stateful implementation of the Shard protocol,
//! handling X25519 handshakes, persistent sessions, and bi-directional encrypted communication.
//!
//! ## Core Components
//! - [`ShardServer`]: A high-concurrency UDP server managing multiple stateful sessions.
//! - [`ShardClient`]: A secure client that performs 1-RTT handshakes and maintains session state.
//! - [`ShardSession`]: A convenience wrapper for established secure channels.
//!
//! ## Example: Basic Server
//! ```rust,no_run
//! use shard_sdk::server::ShardServer;
//! use shard_sdk::config::ShardConfig;
//!
//! #[tokio::main]
//! async fn main() -> tokio::io::Result<()> {
//!     let config = ShardConfig::new([0u8; 32], "0.0.0.0:3000".parse().unwrap());
//!     let server = ShardServer::bind(config).await?;
//!     // server.listen(|payload, responder| { ... }).await?;
//!     Ok(())
//! }
//! ```

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
