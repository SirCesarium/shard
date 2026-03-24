//! Implementation of the send command for Shard CLI.
use crate::state::SessionState;
use base64::{Engine as _, engine::general_purpose};
use miette::{IntoDiagnostic, Result, miette};
use shard_sdk::config::ShardConfig;
use shard_sdk::session::ShardSession;
use std::net::SocketAddr;

/// Executes the send command.
///
/// Resolves the configuration in the following order:
/// 1. Explicit CLI arguments.
/// 2. Environment variables (`SHARD_KEY`).
/// 3. Active session state.
pub async fn exec(message: String, to: Option<SocketAddr>, key: Option<String>) -> Result<()> {
    // 1. Resolve Key
    let raw_key = key
        .or_else(|| std::env::var("SHARD_KEY").ok())
        .or_else(|| SessionState::load().map(|s| s.master_psk))
        .ok_or_else(|| {
            miette!("No Master PSK found. Use --key, set SHARD_KEY, or start a session.")
        })?;

    // 2. Resolve Remote Address
    let addr = to
        .or_else(|| SessionState::load().map(|s| s.remote_addr))
        .ok_or_else(|| miette!("No remote address found. Use --to or start a session."))?;

    // 3. Decode Key
    let mut master_psk = [0u8; 32];
    let decoded = general_purpose::STANDARD
        .decode(raw_key.trim())
        .into_diagnostic()
        .map_err(|_| miette!("Invalid Base64 key provided."))?;

    if decoded.len() != 32 {
        return Err(miette!("Master PSK must be 32 bytes (decoded)."));
    }
    master_psk.copy_from_slice(&decoded);

    // 4. Initialize SDK Session and Send
    let config = ShardConfig::new(master_psk, addr);
    let session = ShardSession::new(config).await.into_diagnostic()?;

    println!("Sending message to {addr}...");
    session
        .send_message(message.as_bytes())
        .await
        .map_err(|e| miette!("Protocol error: {}", e))?;

    println!("Message sent successfully.");
    Ok(())
}
