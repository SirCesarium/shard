//! Implementation of the send command for Shard CLI.
use crate::state::Config;
use base64::{Engine as _, engine::general_purpose};
use miette::{IntoDiagnostic, Result, miette};
use shard_sdk::config::ShardConfig;
use shard_sdk::session::ShardSession;
use tokio::net::lookup_host;

/// Executes the send command.
pub async fn exec(message: String, to: Option<String>, key: Option<String>) -> Result<()> {
    let config_state = Config::load()?;
    let active = config_state.get_active();

    // 1. Resolve Key (Base64)
    let raw_key = if let Some(k) = key {
        if let Some(var_name) = k.strip_prefix("env:") {
            std::env::var(var_name)
                .into_diagnostic()
                .map_err(|_| miette!("Environment variable '{}' not found", var_name))?
        } else {
            k
        }
    } else if let Ok(env_key) = std::env::var("SHARD_KEY") {
        env_key
    } else if let Some((_, s)) = active {
        s.resolve_key()?
    } else {
        return Err(miette!(
            "No Master PSK found. Use --key, set SHARD_KEY, or start a session."
        ));
    };

    // 2. Resolve Remote Address (as String first)
    let addr_str = to
        .or_else(|| active.map(|(_, s)| s.remote_addr.clone()))
        .ok_or_else(|| miette!("No remote address found. Use --to or start a session."))?;

    // 3. DNS Resolution
    let addr = lookup_host(&addr_str)
        .await
        .into_diagnostic()?
        .next()
        .ok_or_else(|| miette!("Could not resolve address: {}", addr_str))?;

    // 4. Decode Key
    let decoded = general_purpose::STANDARD
        .decode(raw_key.trim())
        .into_diagnostic()
        .map_err(|_| miette!("Invalid Base64 key provided."))?;

    if decoded.len() != 32 {
        return Err(miette!("Master PSK must be 32 bytes (decoded)."));
    }
    let mut master_psk = [0u8; 32];
    master_psk.copy_from_slice(&decoded);

    // 5. Initialize SDK Session and Send
    let shard_config = ShardConfig::new(master_psk, addr);
    let session = ShardSession::new(shard_config)
        .await
        .map_err(|e| miette!("Handshake failed: {}", e))?;

    println!("Sending message to {addr} ({addr_str})...");
    session
        .send_message(message.as_bytes())
        .await
        .map_err(|e| miette!("Protocol error: {}", e))?;

    println!("Message sent successfully.");
    Ok(())
}
