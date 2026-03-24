//! Section 3: Anti-Replay & State Control.
use crate::consts::MAX_TIMESTAMP_DRIFT_MS;
use crate::error::ShardError;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// State controller for sequence and timestamp validation.
pub struct Validator {
    last_seq: AtomicU64,
}

impl Validator {
    /// Creates a new validator starting from sequence 0.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last_seq: AtomicU64::new(0),
        }
    }

    /// Validates and commits a frame according to Sections 3.1 and 3.2.
    ///
    /// # Errors
    /// - `ShardError::InvalidSequence`: If `SEQUENCE_ID` <= `LAST_SEQ`.
    /// - `ShardError::TimestampOutOfWindow`: If drift > 5000ms.
    pub fn check_and_update(&self, sequence_id: u64, timestamp: u64) -> Result<(), ShardError> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()))
            .map_err(|_| ShardError::TimestampOutOfWindow)?
            .map_err(|_| ShardError::TimestampOutOfWindow)?;

        // 1. Temporal Windowing (Section 3.2)
        // If the drift is too high, we drop silently via ShardError.
        let drift = now_ms.abs_diff(timestamp);
        if drift > MAX_TIMESTAMP_DRIFT_MS {
            return Err(ShardError::TimestampOutOfWindow);
        }

        // 2. Atomic Sequence Validation and Commit (Section 3.1)
        let mut current = self.last_seq.load(Ordering::Relaxed);
        loop {
            if sequence_id <= current {
                return Err(ShardError::InvalidSequence);
            }

            match self.last_seq.compare_exchange_weak(
                current,
                sequence_id,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(new_val) => current = new_val,
            }
        }
    }
}

impl Default for Validator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequence_monotonicity() {
        let validator = Validator::new();

        // Initial sequence 10 is valid.
        assert!(validator.check_and_update(10, current_ts()).is_ok());

        // Sequence 10 again should fail (Replay).
        assert!(matches!(
            validator.check_and_update(10, current_ts()),
            Err(ShardError::InvalidSequence)
        ));

        // Sequence 5 (old) should fail.
        assert!(matches!(
            validator.check_and_update(5, current_ts()),
            Err(ShardError::InvalidSequence)
        ));

        // Sequence 11 is valid.
        assert!(validator.check_and_update(11, current_ts()).is_ok());
    }

    #[test]
    fn test_timestamp_window_drift() {
        let validator = Validator::new();
        let now = current_ts();

        // Exact time is valid.
        assert!(validator.check_and_update(1, now).is_ok());

        // 4900ms in the past is valid (within 5000ms).
        assert!(validator.check_and_update(2, now - 4900).is_ok());

        // 5100ms in the past is invalid.
        assert!(matches!(
            validator.check_and_update(3, now - 5100),
            Err(ShardError::TimestampOutOfWindow)
        ));

        // 5100ms in the future is invalid.
        assert!(matches!(
            validator.check_and_update(4, now + 5100),
            Err(ShardError::TimestampOutOfWindow)
        ));
    }

    fn current_ts() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
}
