//! Protocol constants as defined in Shard v2.0.

/// Current protocol version.
pub const VERSION: u8 = 0x02;
/// Maximum allowed ciphertext length to ensure MTU compliance (1024 bytes).
pub const MAX_PAYLOAD_SIZE: usize = 1024;
/// Total size of the fixed header in bytes (Offsets 0 to 33).
pub const HEADER_SIZE: usize = 34;
/// Size of the Poly1305 MAC / Authentication Tag.
pub const AUTH_TAG_SIZE: usize = 16;
/// Maximum drift allowed for timestamps (5000ms).
pub const MAX_TIMESTAMP_DRIFT_MS: u64 = 5000;
