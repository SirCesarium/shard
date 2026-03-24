//! Shard asynchronous UDP client implementation.
use crate::config::ShardConfig;
use shard_core::consts::VERSION;
use shard_core::crypto::encrypt_frame_payload;
use shard_core::frame::ShardHeader;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use zerocopy::IntoBytes;
use zerocopy::big_endian::U64;

/// A hardened UDP client for sending encrypted Shard frames.
pub struct ShardClient {
    config: Arc<ShardConfig>,
    socket: Arc<UdpSocket>,
    sequence_id: AtomicU64,
}

impl ShardClient {
    /// Connects a new Shard client to the remote address.
    ///
    /// # Errors
    /// Returns `std::io::Error` if the UDP socket fails to bind or connect.
    pub async fn connect(config: ShardConfig) -> tokio::io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(config.remote_addr).await?;

        Ok(Self {
            config: Arc::new(config),
            socket: Arc::new(socket),
            sequence_id: AtomicU64::new(1),
        })
    }

    /// Encrypts and sends a payload to the server.
    ///
    /// This method automatically handles monotonic sequence ID generation,
    /// current UTC timestamping, and AEAD encryption.
    ///
    /// # Errors
    /// Returns `ShardError` if encryption fails or `std::io::Error` on network failure.
    pub async fn send(&self, payload: &[u8]) -> Result<(), crate::ShardError> {
        let seq = self.sequence_id.fetch_add(1, Ordering::SeqCst);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(0))
            .map_err(|_| crate::ShardError::CryptoError)?;

        let mut header = ShardHeader {
            version: VERSION,
            frame_type: 0x00, // Request
            sequence_id: U64::new(seq),
            timestamp: U64::new(now),
            nonce: [0u8; 12],
            payload_len: 0.into(),
        };

        let mut buffer = payload.to_vec();
        let auth_tag = encrypt_frame_payload(&self.config.master_psk, &mut header, &mut buffer)?;

        let mut packet = Vec::with_capacity(34 + buffer.len() + 16);
        packet.extend_from_slice(header.as_bytes());
        packet.extend_from_slice(&buffer);
        packet.extend_from_slice(&auth_tag);

        self.socket
            .send(&packet)
            .await
            .map_err(|_| crate::ShardError::InvalidFrame)?;

        Ok(())
    }

    /// Returns the remote address this client is connected to.
    #[must_use]
    pub fn remote_addr(&self) -> std::net::SocketAddr {
        self.config.remote_addr
    }
}
