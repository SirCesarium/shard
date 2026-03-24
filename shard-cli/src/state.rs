//! Session state management for the Shard CLI.
use miette::{IntoDiagnostic, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Represents the persistent state of a Shard session.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionState {
    /// The master pre-shared key in base64.
    pub master_psk: String,
    /// The default remote address for this session.
    pub remote_addr: SocketAddr,
    /// Unix timestamp when this session should be considered expired.
    pub expires_at: u64,
}

impl SessionState {
    /// Returns the path to the temporary session file.
    fn path() -> PathBuf {
        std::env::temp_dir().join(".shard_session.toml")
    }

    /// Saves the session state to a temporary file.
    pub fn save(&self) -> Result<()> {
        let content = toml::to_string(self).into_diagnostic()?;
        std::fs::write(Self::path(), content).into_diagnostic()?;
        Ok(())
    }

    /// Loads the session state if it exists and hasn't expired.
    pub fn load() -> Option<Self> {
        let content = std::fs::read_to_string(Self::path()).ok()?;
        let state: Self = toml::from_str(&content).ok()?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();

        if state.expires_at > now {
            Some(state)
        } else {
            let _ = std::fs::remove_file(Self::path());
            None
        }
    }

    /// Deletes the current session file.
    pub fn clear() {
        let _ = std::fs::remove_file(Self::path());
    }
}
