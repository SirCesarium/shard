//! Section 3: Anti-Replay & State Control.
use crate::error::ShardError;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// State controller for sequence and timestamp validation.
pub struct Validator {
    last_seq: AtomicU64,
    drift_window_ms: u64,
}

impl Validator {
    /// Creates a new validator with the specified drift window and starting sequence 0.
    #[must_use]
    pub const fn new(drift_window_ms: u64) -> Self {
        Self {
            last_seq: AtomicU64::new(0),
            drift_window_ms,
        }
    }

    /// Validates and commits a frame according to Sections 3.1 and 3.2.
    ///
    /// # Errors
    /// - `ShardError::InvalidSequence`: If `SEQUENCE_ID` <= `LAST_SEQ`.
    /// - `ShardError::TimestampOutOfWindow`: If drift > `drift_window_ms`.
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
        if drift > self.drift_window_ms {
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
        Self::new(crate::consts::MAX_TIMESTAMP_DRIFT_MS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::MAX_TIMESTAMP_DRIFT_MS;

    fn current_ts() -> u64 {
        #[allow(clippy::expect_used)]
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System clock failure: could not calculate duration since UNIX_EPOCH");

        #[allow(clippy::expect_used)]
        u64::try_from(duration.as_millis()).expect("System clock failure: timestamp overflowed u64")
    }

    #[test]
    fn test_sequence_monotonicity() {
        let validator = Validator::new(MAX_TIMESTAMP_DRIFT_MS);

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
        let validator = Validator::new(MAX_TIMESTAMP_DRIFT_MS);
        // We use a manual check against drift since the validator uses SystemTime::now() internally.
        // To make this test deterministic, we must be very close to 'now'.
        let now = current_ts();

        // Exact time is valid.
        assert!(validator.check_and_update(1, now).is_ok());

        // 2000ms in the past is valid (well within 5000ms).
        assert!(validator.check_and_update(2, now - 2000).is_ok());

        // 10000ms in the past is invalid.
        assert!(matches!(
            validator.check_and_update(3, now - 10000),
            Err(ShardError::InvalidFrame)
        ));

        // 10000ms in the future is invalid.
        assert!(matches!(
            validator.check_and_update(4, now + 10000),
            Err(ShardError::InvalidFrame)
        ));
    }

    #[test]
    fn test_network_reordering_regression() {
        let validator = Validator::new(MAX_TIMESTAMP_DRIFT_MS);
        let now = current_ts();

        // Packet 2 arrives first (valid)
        assert!(validator.check_and_update(2, now).is_ok());

        // Packet 1 arrives late (invalid/replay)
        assert!(matches!(
            validator.check_and_update(1, now),
            Err(ShardError::InvalidFrame)
        ));

        // Packet 3 arrives (valid)
        assert!(validator.check_and_update(3, now).is_ok());
    }

    #[test]
    fn test_concurrent_sequence_updates() {
        use std::sync::Arc;
        use std::thread;

        let validator = Arc::new(Validator::new(MAX_TIMESTAMP_DRIFT_MS));
        let mut handles = vec![];

        for i in 1..=100 {
            let v = Arc::clone(&validator);
            handles.push(thread::spawn(move || {
                // Ignore errors from race conditions, we just want to ensure
                // that at the end the last_seq is 100.
                let _ = v.check_and_update(i, current_ts());
            }));
        }

        for handle in handles {
            assert!(handle.join().is_ok(), "Test thread panicked unexpectedly");
        }

        assert_eq!(validator.last_seq.load(Ordering::SeqCst), 100);
    }
}

#[cfg(test)]
mod benches {
    use super::*;
    use crate::consts::MAX_TIMESTAMP_DRIFT_MS;

    #[allow(dead_code)]
    fn bench_validation() {
        let validator = Validator::new(MAX_TIMESTAMP_DRIFT_MS);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        for i in 1..1000 {
            let _ = validator.check_and_update(i, now);
        }
    }
}
