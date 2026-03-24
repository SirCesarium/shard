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
        #[cfg(debug_assertions)]
        let internal_error = |e: &str| {
            println!("[DEBUG] Validation drop: {e}");
            ShardError::InvalidFrame
        };
        #[cfg(not(debug_assertions))]
        let internal_error = |_e: &str| ShardError::InvalidFrame;

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()))
            .map_err(|_| internal_error("Clock error"))?
            .map_err(|_| internal_error("Clock overflow"))?;

        // 1. Temporal Windowing (Section 3.2)
        // If the drift is too high, we drop silently via ShardError.
        let drift = now_ms.abs_diff(timestamp);
        if drift > MAX_TIMESTAMP_DRIFT_MS {
            return Err(internal_error("Timestamp drift too high"));
        }

        // 2. Atomic Sequence Validation and Commit (Section 3.1)
        let mut current = self.last_seq.load(Ordering::Relaxed);
        loop {
            if sequence_id <= current {
                return Err(internal_error("Sequence ID replay or regression"));
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
            Err(ShardError::InvalidFrame)
        ));

        // Sequence 5 (old) should fail.
        assert!(matches!(
            validator.check_and_update(5, current_ts()),
            Err(ShardError::InvalidFrame)
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
            Err(ShardError::InvalidFrame)
        ));

        // 5100ms in the future is invalid.
        assert!(matches!(
            validator.check_and_update(4, now + 5100),
            Err(ShardError::InvalidFrame)
        ));

        // Exact 5000ms drift should be valid (inclusive boundary)
        assert!(validator.check_and_update(5, now - 5000).is_ok());
    }

    #[test]
    fn test_network_reordering_regression() {
        let validator = Validator::new();
        let now = current_ts();

        // Packet 2 arrives first (valid)
        assert!(validator.check_and_update(2, now).is_ok());

        // Packet 1 arrives late (must be rejected as regression)
        assert!(matches!(
            validator.check_and_update(1, now),
            Err(ShardError::InvalidFrame)
        ));

        // Packet 3 arrives (valid)
        assert!(validator.check_and_update(3, now).is_ok());
    }

    #[test]
    fn test_concurrent_sequence_updates() -> Result<(), String> {
        use std::sync::Arc;
        use std::thread;

        let validator = Arc::new(Validator::new());
        let mut handles = vec![];

        for i in 1..=100 {
            let v = Arc::clone(&validator);
            let h = thread::spawn(move || {
                // Each thread tries to update to its own index
                let _ = v.check_and_update(i, current_ts());
            });
            handles.push(h);
        }

        for h in handles {
            h.join().map_err(|_| "Thread panicked".to_string())?;
        }

        // After all threads, the last_seq must be at most 100
        // (Since they all sent unique IDs 1-100)
        if validator.last_seq.load(Ordering::SeqCst) > 100 {
            return Err("Sequence exceeded maximum expected value".to_string());
        }

        if validator.last_seq.load(Ordering::SeqCst) == 0 {
            return Err("No sequence updates were recorded".to_string());
        }

        Ok(())
    }

    fn current_ts() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
}
