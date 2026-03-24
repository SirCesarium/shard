//! Implementation of the listen command for Shard CLI.
use crate::state::SessionState;
use base64::{engine::general_purpose, Engine as _};
use miette::{miette, IntoDiagnostic, Result};
use shard_sdk::config::ShardConfig;
use shard_sdk::server::ShardServer;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Executes the listen command to start a Shard server.
///
/// Key resolution priority:
/// 1. Explicit CLI argument (--key).
/// 2. Environment variable (`SHARD_KEY`).
/// 3. Active session state.
pub async fn exec(port: u16, key: Option<String>) -> Result<()> {
    // 1. Resolve Key
    let raw_key = key
        .or_else(|| std::env::var("SHARD_KEY").ok())
        .or_else(|| SessionState::load().map(|s| s.master_psk))
        .ok_or_else(|| miette!("No Master PSK found. Use --key, set SHARD_KEY, or start a session."))?;

    // 2. Decode Key
    let mut master_psk = [0u8; 32];
    let decoded = general_purpose::STANDARD
        .decode(raw_key.trim())
        .into_diagnostic()
        .map_err(|_| miette!("Invalid Base64 key provided."))?;

    if decoded.len() != 32 {
        return Err(miette!("Master PSK must be 32 bytes (decoded)."));
    }
    master_psk.copy_from_slice(&decoded);

    // 3. Initialize Server
    // We bind to 0.0.0.0 to listen on all interfaces.
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    let config = ShardConfig::new(master_psk, addr);
    let server = ShardServer::bind(config).await.into_diagnostic()?;

    println!("Shard server listening on {addr}");
    println!("Encryption: ChaCha20-Poly1305");
    println!("Press Ctrl+C to stop.");

    // 4. Start processing loop
    server
        .listen(|payload| {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            if let Ok(msg) = String::from_utf8(payload) {
                println!("[{timestamp}] Received: {msg}");
            } else {
                println!("[{timestamp}] Received binary data (hex parsing omitted)");
            }
        })
        .await
        .into_diagnostic()?;

    Ok(())
}
