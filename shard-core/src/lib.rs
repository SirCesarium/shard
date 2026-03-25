//! # Shard Core
//!
//! Foundational primitives for the Shard Protocol v2.0.
//!
//! This crate implements the byte-level definitions, cryptographic algorithms,
//! and validation logic required by the Shard specification. It is designed
//! for zero-copy efficiency and minimal overhead.
//!
//! ## Modules
//! - [`frame`]: Binary frame representation and parsing.
//! - [`crypto`]: AEAD (ChaCha20-Poly1305), HKDF, and X25519 primitives.
//! - [`validation`]: Anti-replay and temporal drift control.
//!
//! ## Technical Architecture
//! All structures use `repr(C, packed)` and `zerocopy` to ensure that
//! network bytes can be cast directly into Rust structs with near-zero latency.

#![deny(clippy::all, clippy::pedantic, clippy::nursery, missing_docs)]

pub mod consts;
pub mod crypto;
pub mod error;
pub mod frame;
pub mod types;
pub mod validation;

pub use crate::error::ShardError;
pub use crate::frame::FrameType;
