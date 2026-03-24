//! Shard primitive types and enums.

/// Frame types as defined in Section 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Request (0x00).
    Request = 0x00,
    /// Response (0x01).
    Response = 0x01,
    /// Error (0x02).
    Error = 0x02,
}

/// Error codes for Error frames as defined in Section 5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtocolError {
    /// `AUTH_FAILURE` (0x01).
    /// INTERNAL USE ONLY. Do not transmit over the network per Section 2.3 (Silent Drop).
    AuthFailure = 0x01,
    /// `REPLAY_DETECTED` (0x02). Sequence ID or Timestamp violation.
    ReplayDetected = 0x02,
    /// `DECRYPTION_FAILED` (0x03). Internal cryptographic error.
    DecryptionFailed = 0x03,
    /// `EXECUTION_TIMEOUT` (0x04). Payload processing exceeded deadline.
    ExecutionTimeout = 0x04,
    /// `MALFORMED_FRAME` (0x05). Length mismatch or invalid version.
    MalformedFrame = 0x05,
    /// `PAYLOAD_TOO_LARGE` (0x06). Exceeds the 1024-byte limit.
    PayloadTooLarge = 0x06,
}
