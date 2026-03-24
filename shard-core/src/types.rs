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
///
/// Note: 0x01 (`AUTH_FAILURE`) is omitted as it must be dropped silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtocolError {
    /// Replay detected (0x02).
    ReplayDetected = 0x02,
    /// Decryption failed (0x03).
    DecryptionFailed = 0x03,
    /// Execution timeout (0x04).
    ExecutionTimeout = 0x04,
    /// Malformed frame (0x05).
    MalformedFrame = 0x05,
    /// Payload too large (0x06).
    PayloadTooLarge = 0x06,
}
