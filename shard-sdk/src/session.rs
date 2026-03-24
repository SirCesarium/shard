//! Shard session management for persistent secure channels.
use crate::client::ShardClient;
use crate::config::ShardConfig;
use std::sync::Arc;

/// Represents an established secure session over UDP.
pub struct ShardSession {
    inner: Arc<ShardClient>,
}

impl ShardSession {
    /// Creates a new session from a configuration.
    ///
    /// # Errors
    /// Returns `std::io::Error` if the underlying UDP socket cannot be initialized.
    pub async fn new(config: ShardConfig) -> tokio::io::Result<Self> {
        let client = ShardClient::connect(config).await?;
        Ok(Self {
            inner: Arc::new(client),
        })
    }

    /// Sends a secure message through the session.
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
