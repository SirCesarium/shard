//! # Shard Core
//!
//! Internal primitives for the Shard Protocol.

#![deny(clippy::all, clippy::pedantic, clippy::nursery, missing_docs)]

pub mod consts;
pub mod error;
pub mod types;
pub mod frame;
pub mod crypto;

pub use crate::error::ShardError;
pub use crate::types::{FrameType, ProtocolError};
