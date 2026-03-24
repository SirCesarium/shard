//! Error types for the library implementation.

use thiserror::Error;

/// Errors that can occur during frame processing or crypto operations.
#[derive(Debug, Error)]
pub enum ShardError {
    /// Provided buffer is smaller than the required 34 bytes.
    #[error("Buffer too small to contain a header")]
    BufferTooSmall,

    /// Cryptographic failure (Section 2.1 and 2.2).
    #[error("Cryptographic operation failed (HKDF/AEAD)")]
    CryptoError,

    /// Version mismatch found during parsing (Section 1).
    #[error("Unsupported protocol version: expected {expected}, found {found}")]
    InvalidVersion {
        /// The version we expect (0x01).
        expected: u8,
        /// The version we got.
        found: u8
    },

    /// The sequence ID is lower or equal to the last one (Section 3.1).
    #[error("Replay detected or invalid sequence ID")]
    InvalidSequence,

    /// Timestamp is outside the allowed drift window (Section 3.2).
    #[error("Timestamp drift too high")]
    TimestampOutOfWindow,

    /// Payload exceeds the 1024-byte limit defined for MTU compliance (Section 2.3).
    #[error("Payload exceeds the maximum allowed size: {0} bytes")]
    PayloadTooLarge(usize),

    /// The payload length field in the header is invalid or inconsistent.
    #[error("Invalid payload length in header")]
    InvalidPayloadLength,
}
