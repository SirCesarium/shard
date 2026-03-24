//! Shard configuration and security parameters.
use std::net::SocketAddr;

/// Configuration for a Shard endpoint.
#[derive(Debug, Clone)]
pub struct ShardConfig {
    /// The 32-byte Pre-Shared Key used for HKDF and AEAD.
    pub master_psk: [u8; 32],
    /// The target address for the UDP socket.
    pub remote_addr: SocketAddr,
    /// Maximum allowed clock drift for timestamp validation (milliseconds).
    pub drift_window_ms: u64,
    /// The starting sequence ID for a new session.
    pub initial_sequence_id: u64,
}

impl ShardConfig {
    /// Creates a new configuration instance.
    #[must_use]
    pub const fn new(master_psk: [u8; 32], remote_addr: SocketAddr) -> Self {
        Self {
            master_psk,
            remote_addr,
            drift_window_ms: 5000,
            initial_sequence_id: 1,
        }
    }

    /// Sets a custom starting sequence ID for this configuration.
    #[must_use]
    pub const fn with_sequence_id(mut self, sequence_id: u64) -> Self {
        self.initial_sequence_id = sequence_id;
        self
    }
}
