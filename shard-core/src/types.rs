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
/// IMPORTANT: Section 2.3 mandates SILENT DROP for:
/// - Version mismatch
/// - Timestamp drift
/// - Sequence replay
/// - AEAD Authentication failure
/// - `No ProtocolError` codes exist for these to prevent side-channel leaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtocolError {
    /// Generic execution error after successful decryption (0x01).
    ExecutionError = 0x01,
    /// Execution timeout (0x04).
    ExecutionTimeout = 0x04,
    /// The actual operation requested failed (0x07).
    ProcessingFailed = 0x07,
}
