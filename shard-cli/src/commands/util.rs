use crate::state::Config;
use base64::{Engine as _, engine::general_purpose};
use miette::{IntoDiagnostic, Result, miette};
use std::net::SocketAddr;
use tokio::net::lookup_host;

/// Resolves the Master PSK and Remote Address based on CLI args, environment, or active session.
pub async fn resolve_target(
    to: Option<String>,
    key: Option<String>,
) -> Result<([u8; 32], SocketAddr, String)> {
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

    // 2. Resolve Remote Address
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

    Ok((master_psk, addr, addr_str))
}
