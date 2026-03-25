//! Shard asynchronous UDP server implementation with stateful session management.
use crate::config::ShardConfig;
use dashmap::DashMap;
use shard_core::crypto::agreement::{compute_shared_secret, generate_ephemeral_keypair};
use shard_core::crypto::hkdf::derive_session_key_v2;
use shard_core::crypto::{decrypt_frame_payload, encrypt_frame_payload};
use shard_core::frame::{FrameType, ShardFrame, ShardHeader};
use shard_core::validation::Validator;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use zerocopy::IntoBytes;
use zerocopy::big_endian::{U32, U64};

/// Represents an active stateful session on the server.
struct PeerSession {
    session_key: [u8; 32],
    validator: Validator,
}

/// A hardened UDP server that manages stateful Shard 2.0 sessions.
pub struct ShardServer {
    config: Arc<ShardConfig>,
    socket: Arc<UdpSocket>,
    /// Map of peer addresses to their respective session state.
    sessions: Arc<DashMap<SocketAddr, PeerSession>>,
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
            sessions: Arc::new(DashMap::new()),
        })
    }

    /// Starts the server loop and processes incoming packets.
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
            let (n, peer) = self.socket.recv_from(&mut buf).await?;
            let data = buf[..n].to_vec();

            let config = Arc::clone(&self.config);
            let sessions = Arc::clone(&self.sessions);
            let h_callback = Arc::clone(&handler);
            let socket_task = Arc::clone(&self.socket);

            tokio::spawn(async move {
                Self::process_packet(data, peer, config, sessions, socket_task, h_callback).await;
            });
        }
    }

    async fn process_packet<F>(
        data: Vec<u8>,
        peer: SocketAddr,
        config: Arc<ShardConfig>,
        sessions: Arc<DashMap<SocketAddr, PeerSession>>,
        socket: Arc<UdpSocket>,
        handler: Arc<F>,
    ) where
        F: Fn(Vec<u8>) + Send + Sync + 'static,
    {
        // 1. Basic Frame Parsing
        let Ok(frame) = ShardFrame::from_bytes(&data) else {
            return;
        };

        let Ok(frame_type) = FrameType::try_from(frame.header.frame_type) else {
            return;
        };

        match frame_type {
            FrameType::HandshakeInit => {
                Self::handle_handshake(&frame, peer, &config, &sessions, &socket).await;
            }
            FrameType::Data => {
                Self::handle_data(&frame, peer, &sessions, &handler);
            }
            _ => {} // Ignore other types for now
        }
    }

    async fn handle_handshake(
        frame: &ShardFrame<'_>,
        peer: SocketAddr,
        config: &Arc<ShardConfig>,
        sessions: &Arc<DashMap<SocketAddr, PeerSession>>,
        socket: &Arc<UdpSocket>,
    ) {
        // Handshake Init is encrypted with Master PSK
        let mut payload = frame.ciphertext.to_vec();
        if decrypt_frame_payload(
            &config.master_psk,
            &frame.header,
            &mut payload,
            &frame.auth_tag,
        )
        .is_err()
        {
            return;
        }

        if payload.len() != 32 {
            return;
        }
        let mut client_pub = [0u8; 32];
        client_pub.copy_from_slice(&payload);

        // Generate server keypair
        let Ok(kp) = generate_ephemeral_keypair() else {
            return;
        };
        let (server_priv, server_pub) = kp;

        // Compute shared secret and session key
        let Ok(shared_secret) = compute_shared_secret(server_priv, &client_pub) else {
            return;
        };
        let Ok(session_key) = derive_session_key_v2(&shared_secret, &config.master_psk) else {
            return;
        };

        // Store session
        sessions.insert(
            peer,
            PeerSession {
                session_key,
                validator: Validator::new(),
            },
        );

        // Send Handshake Response (Encrypted with Master PSK)
        let mut response_payload = server_pub.to_vec();
        let mut response_header = ShardHeader {
            version: shard_core::consts::VERSION,
            frame_type: FrameType::HandshakeResponse as u8,
            sequence_id: U64::new(0),
            timestamp: U64::new(0),
            nonce: [0u8; 12],
            payload_len: U32::new(32),
        };
        rand::fill(&mut response_header.nonce);

        let Ok(tag) = encrypt_frame_payload(
            &config.master_psk,
            &mut response_header,
            &mut response_payload,
        ) else {
            return;
        };

        let mut packet = Vec::new();
        packet.extend_from_slice(response_header.as_bytes());
        packet.extend_from_slice(&response_payload);
        packet.extend_from_slice(&tag);

        let _ = socket.send_to(&packet, peer).await;
    }

    fn handle_data<F>(
        frame: &ShardFrame<'_>,
        peer: SocketAddr,
        sessions: &Arc<DashMap<SocketAddr, PeerSession>>,
        handler: &Arc<F>,
    ) where
        F: Fn(Vec<u8>) + Send + Sync + 'static,
    {
        // Retrieve session
        let Some(session) = sessions.get(&peer) else {
            return;
        };

        // 2. Sequence and Temporal Validation (Per-session validator)
        if session
            .validator
            .check_and_update(frame.header.sequence_id.get(), frame.header.timestamp.get())
            .is_err()
        {
            return;
        }

        // 3. Decryption with Session Key
        let mut ciphertext = frame.ciphertext.to_vec();
        if decrypt_frame_payload(
            &session.session_key,
            &frame.header,
            &mut ciphertext,
            &frame.auth_tag,
        )
        .is_err()
        {
            return;
        }

        // Explicitly drop session to tighten significant drop (Clippy)
        drop(session);

        handler(ciphertext);
    }
}
