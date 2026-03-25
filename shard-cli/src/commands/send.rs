//! Implementation of the send command for Shard CLI.
use crate::commands::util::resolve_target;
use miette::{Result, miette};
use shard_sdk::config::ShardConfig;
use shard_sdk::session::ShardSession;

/// Executes the send command.
pub async fn exec(message: String, to: Option<String>, key: Option<String>, drift: u64) -> Result<()> {
    let (master_psk, addr, addr_str) = resolve_target(to, key).await?;

    // 1. Initialize SDK Session (Handshake)
    let mut shard_config = ShardConfig::new(master_psk, addr);
    shard_config.drift_window_ms = drift;
    let session = ShardSession::new(shard_config)
        .await
        .map_err(|e| miette!("Handshake failed: {}", e))?;

    // 2. Send Message
    println!("Sending message to {addr} ({addr_str})...");
    session
        .send_message(message.as_bytes())
        .await
        .map_err(|e| miette!("Protocol error: {}", e))?;

    println!("Message sent successfully.");
    Ok(())
}
