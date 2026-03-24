//! Shard asynchronous UDP server implementation.
use crate::config::ShardConfig;
use shard_core::crypto::decrypt_frame_payload;
use shard_core::frame::ShardFrame;
use shard_core::validation::Validator;
use std::sync::Arc;
use tokio::net::UdpSocket;

/// A hardened UDP server that validates and decrypts Shard frames.
pub struct ShardServer {
    config: Arc<ShardConfig>,
    socket: Arc<UdpSocket>,
    validator: Arc<Validator>,
}

impl ShardServer {
    /// Binds a new Shard server to the configured address.
    ///
    /// # Errors
    /// Returns `std::io::Error` if the UDP socket fails to bind.
    pub async fn bind(config: ShardConfig) -> tokio::io::Result<Self> {
        let socket = UdpSocket::bind(config.remote_addr).await?;
        Ok(Self {
            config: Arc::new(config),
            socket: Arc::new(socket),
            validator: Arc::new(Validator::new()),
        })
    }

    /// Starts the server loop and processes incoming packets.
    ///
    /// This method accepts a handler closure to process decrypted payloads.
    /// Note: The handler is wrapped in an `Arc` to allow shared access across
    /// multiple asynchronous tasks.
    ///
    /// # Errors
    /// Returns `std::io::Error` if packet reception fails.
    pub async fn listen<F>(&self, handler: F) -> tokio::io::Result<()>
    where
        F: Fn(Vec<u8>) + Send + Sync + 'static,
    {
        let mut buf = [0u8; 2048];
        let handler = Arc::new(handler);

        loop {
            let (n, _peer) = self.socket.recv_from(&mut buf).await?;
            let data = buf[..n].to_vec();

            // Clone atomic references for the task
            let config = Arc::clone(&self.config);
            let validator = Arc::clone(&self.validator);
            let h_callback = Arc::clone(&handler);

            tokio::spawn(async move {
                // 1. Frame Parsing
                let Ok(frame) = ShardFrame::from_bytes(&data) else {
                    return; // Silent Drop
                };

                // 2. Sequence and Temporal Validation
                if validator
                    .check_and_update(frame.header.sequence_id.get(), frame.header.timestamp.get())
                    .is_err()
                {
                    return; // Silent Drop
                }

                // 3. Cryptographic Decryption (AEAD)
                let mut ciphertext = frame.ciphertext.to_vec();
                if decrypt_frame_payload(
                    &config.master_psk,
                    &frame.header,
                    &mut ciphertext,
                    &frame.auth_tag,
                )
                .is_err()
                {
                    return; // Silent Drop
                }

                // 4. Execution of the decrypted plaintext
                h_callback(ciphertext);
            });
        }
    }
}
