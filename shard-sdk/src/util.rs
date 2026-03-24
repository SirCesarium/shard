//! Helper utilities for Shard protocol operations.
use crate::ShardError;
use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current Unix timestamp in milliseconds.
///
/// # Errors
/// Returns `ShardError::CryptoError` if the system clock is set before UNIX EPOCH.
pub fn current_timestamp_ms() -> Result<u64, ShardError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(0))
        .map_err(|_| ShardError::CryptoError)
}

/// Validates if a given timestamp is within the allowed drift window.
#[must_use]
pub fn is_within_window(ts: u64, drift_window: u64) -> bool {
    let now = current_timestamp_ms().unwrap_or(0);
    now.abs_diff(ts) <= drift_window
}
