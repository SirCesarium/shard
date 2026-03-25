//! Implementation of the listen command for Shard CLI.
use crate::state::Config;
use base64::{Engine as _, engine::general_purpose};
use miette::{IntoDiagnostic, Result, miette};
use shard_sdk::config::ShardConfig;
use shard_sdk::server::ShardServer;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Executes the listen command to start a Shard server.
pub async fn exec(port: u16, key: Option<String>, drift: u64) -> Result<()> {
    let config_state = Config::load()?;
    let active = config_state.get_active();

    // 1. Resolve Key
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
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    let mut shard_config = ShardConfig::new(master_psk, addr);
    shard_config.drift_window_ms = drift;
    let server = ShardServer::bind(shard_config).await.into_diagnostic()?;

    println!("Shard server listening on {addr}");
    println!("Encryption: ChaCha20-Poly1305");
    println!("Press Ctrl+C to stop.");

    // 4. Start processing loop
    server
        .listen(|payload, responder| {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            if let Ok(msg) = String::from_utf8(payload) {
                println!("[{timestamp}] Received: {msg}");

                // Example: Automated response
                let response = format!("Command acknowledged: {msg}");
                tokio::spawn(async move {
                    let _ = responder.send(response.as_bytes()).await;
                });
            } else {
                println!("[{timestamp}] Received binary data");
            }
        })
        .await
        .into_diagnostic()?;

    Ok(())
}
