//! Shard session management for persistent secure channels.
use crate::client::ShardClient;
use crate::config::ShardConfig;
use std::sync::Arc;

/// Represents an established stateful secure session over UDP.
pub struct ShardSession {
    inner: Arc<ShardClient>,
}

impl ShardSession {
    /// Creates a new stateful session from a configuration.
    /// Performs an X25519 handshake to establish Perfect Forward Secrecy.
    ///
    /// # Errors
    /// Returns an error if the handshake or socket initialization fails.
    pub async fn new(config: ShardConfig) -> Result<Self, String> {
        let client = ShardClient::connect(config).await?;
        Ok(Self {
            inner: Arc::new(client),
        })
    }

    /// Sends a secure message through the established stateful session.
    ///
    /// # Errors
    /// Returns `ShardError` if encryption or transmission fails.
    pub async fn send_message(&self, data: &[u8]) -> Result<(), crate::ShardError> {
        self.inner.send(data).await
    }

    /// Returns the current (next) sequence ID for this session.
    #[must_use]
    pub fn current_sequence(&self) -> u64 {
        self.inner.current_sequence()
    }

    /// Returns the remote address this client is connected to.
    #[must_use]
    pub fn remote_addr(&self) -> std::net::SocketAddr {
        self.inner.remote_addr()
    }
}
