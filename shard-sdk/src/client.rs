//! Shard asynchronous UDP client implementation.
use crate::config::ShardConfig;
use shard_core::crypto::agreement::{compute_shared_secret, generate_ephemeral_keypair};
use shard_core::crypto::hkdf::derive_session_key_v2;
use shard_core::crypto::{decrypt_frame_payload, encrypt_frame_payload};
use shard_core::frame::{FrameType, ShardFrame, ShardHeader};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use zerocopy::IntoBytes;
use zerocopy::big_endian::{U32, U64};

/// A hardened UDP client for sending encrypted Shard frames.
pub struct ShardClient {
    config: Arc<ShardConfig>,
    socket: Arc<UdpSocket>,
    sequence_id: AtomicU64,
    session_key: [u8; 32],
}

impl ShardClient {
    /// Connects and performs a handshake with the remote Shard server.
    ///
    /// # Errors
    /// Returns an error string if the handshake or socket initialization fails.
    pub async fn connect(config: ShardConfig) -> Result<Self, String> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("Socket bind failed: {e}"))?;
        socket
            .connect(config.remote_addr)
            .await
            .map_err(|e| format!("Socket connect failed: {e}"))?;

        // 1. Handshake Init
        let (client_priv, client_pub) =
            generate_ephemeral_keypair().map_err(|e| format!("Keypair gen failed: {e}"))?;
        let mut init_payload = client_pub.to_vec();
        let mut init_header = ShardHeader {
            version: shard_core::consts::VERSION,
            frame_type: FrameType::HandshakeInit as u8,
            sequence_id: U64::new(0),
            timestamp: U64::new(0),
            nonce: [0u8; 12],
            payload_len: U32::new(32),
        };
        rand::fill(&mut init_header.nonce);

        let init_tag =
            encrypt_frame_payload(&config.master_psk, &mut init_header, &mut init_payload)
                .map_err(|e| format!("Init encryption failed: {e}"))?;

        let mut init_packet = Vec::new();
        init_packet.extend_from_slice(init_header.as_bytes());
        init_packet.extend_from_slice(&init_payload);
        init_packet.extend_from_slice(&init_tag);

        socket
            .send(&init_packet)
            .await
            .map_err(|e| format!("Init send failed: {e}"))?;

        // 2. Wait for Handshake Response
        let mut buf = [0u8; 2048];
        let n = timeout(Duration::from_secs(5), socket.recv(&mut buf))
            .await
            .map_err(|_| "Handshake timed out".to_string())?
            .map_err(|e| format!("Handshake recv failed: {e}"))?;
        let response_data = &buf[..n];

        let frame = ShardFrame::from_bytes(response_data)
            .map_err(|e| format!("Invalid handshake response: {e}"))?;
        if frame.header.frame_type != FrameType::HandshakeResponse as u8 {
            return Err("Unexpected frame type during handshake".to_string());
        }

        let mut server_pub_payload = frame.ciphertext.to_vec();
        decrypt_frame_payload(
            &config.master_psk,
            &frame.header,
            &mut server_pub_payload,
            &frame.auth_tag,
        )
        .map_err(|e| format!("Response decryption failed: {e}"))?;

        if server_pub_payload.len() != 32 {
            return Err("Invalid server public key length".to_string());
        }
        let mut server_pub = [0u8; 32];
        server_pub.copy_from_slice(&server_pub_payload);

        // 3. Derive Session Key
        let shared_secret = compute_shared_secret(client_priv, &server_pub)
            .map_err(|e| format!("Shared secret computation failed: {e}"))?;
        let session_key = derive_session_key_v2(&shared_secret, &config.master_psk)
            .map_err(|e| format!("Session key derivation failed: {e}"))?;

        Ok(Self {
            sequence_id: AtomicU64::new(1), // Data starts at 1
            config: Arc::new(config),
            socket: Arc::new(socket),
            session_key,
        })
    }

    /// Returns the current (next) sequence ID for this client.
    #[must_use]
    pub fn current_sequence(&self) -> u64 {
        self.sequence_id.load(Ordering::Relaxed)
    }

    /// Encrypts and sends a payload to the server.
    ///
    /// # Errors
    /// Returns `ShardError` if encryption fails or `std::io::Error` on network failure.
    pub async fn send(&self, payload: &[u8]) -> Result<(), crate::ShardError> {
        let seq = self.sequence_id.fetch_add(1, Ordering::SeqCst);

        if seq == u64::MAX {
            return Err(crate::ShardError::InvalidSequence);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(0))
            .map_err(|_| crate::ShardError::CryptoError)?;

        let mut nonce = [0u8; 12];
        rand::fill(&mut nonce);

        let payload_len_usize = payload.len();
        if payload_len_usize > shard_core::consts::MAX_PAYLOAD_SIZE {
            return Err(crate::ShardError::PayloadTooLarge(payload_len_usize));
        }

        let payload_len_u32: u32 = payload_len_usize
            .try_into()
            .map_err(|_| crate::ShardError::InvalidPayloadLength)?;

        let mut header = ShardHeader {
            version: shard_core::consts::VERSION,
            frame_type: FrameType::Data as u8,
            sequence_id: U64::new(seq),
            timestamp: U64::new(now),
            nonce,
            payload_len: U32::new(payload_len_u32),
        };

        let mut buffer = payload.to_vec();
        let auth_tag = encrypt_frame_payload(&self.session_key, &mut header, &mut buffer)?;

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
