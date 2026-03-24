//! Implementation of the session command for Shard CLI.
use crate::state::SessionState;
use miette::{IntoDiagnostic, Result};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Creates a new temporary session.
pub fn exec(name: &str, to: SocketAddr, key: String) -> Result<()> {
    // Session expires in 8 hours by default.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .into_diagnostic()?;

    let expires_at = now.as_secs() + (8 * 3600);

    let state = SessionState {
        master_psk: key,
        remote_addr: to,
        expires_at,
    };

    state.save()?;

    println!("Session '{name}' established.");
    println!("Destination: {to}");
    println!("This session will expire in 8 hours or upon calling 'exit'.");

    if std::env::var("SHARD_KEY").is_err() {
        println!("\n[!] Hint: You can also set the SHARD_KEY env var for global use.");
    }

    Ok(())
}
