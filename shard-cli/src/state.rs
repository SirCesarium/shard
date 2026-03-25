//! Persistent state management for Shard CLI sessions.
use miette::{miette, IntoDiagnostic, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// Represents a single named session configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Session {
    /// The master pre-shared key (can be Base64 or an 'env:VAR' reference).
    pub master_psk: String,
    /// The remote address (supports domain names).
    pub remote_addr: String,
}

impl Session {
    /// Resolves the master PSK. If it starts with 'env:', it fetches the value from
    /// the environment. Otherwise, returns the stored string.
    pub fn resolve_key(&self) -> Result<String> {
        if let Some(var_name) = self.master_psk.strip_prefix("env:") {
            std::env::var(var_name)
                .into_diagnostic()
                .map_err(|_| miette!("Environment variable '{}' not found", var_name))
        } else {
            Ok(self.master_psk.clone())
        }
    }
}

/// The global persistent state for Shard CLI.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Config {
    /// Name of the currently active session.
    pub active_session: Option<String>,
    /// Map of named sessions.
    pub sessions: HashMap<String, Session>,
}

impl Config {
    fn path() -> Result<PathBuf> {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .ok_or_else(|| miette!("Could not determine home directory"))?;
        
        let path = PathBuf::from(home).join(".shard");
        if !path.exists() {
            fs::create_dir_all(&path).into_diagnostic()?;
        }
        Ok(path.join("config.toml"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(path).into_diagnostic()?;
        let config: Config = toml::from_str(&content).into_diagnostic()?;
        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        let content = toml::to_string(self).into_diagnostic()?;
        fs::write(path, content).into_diagnostic()?;
        Ok(())
    }

    pub fn get_active(&self) -> Option<(&String, &Session)> {
        let name = self.active_session.as_ref()?;
        self.sessions.get(name).map(|s| (name, s))
    }

    pub fn set_session(&mut self, name: String, to: String, key: String) {
        let session = Session {
            master_psk: key,
            remote_addr: to,
        };
        self.sessions.insert(name.clone(), session);
        self.active_session = Some(name);
    }

    pub fn use_session(&mut self, name: &str) -> Result<()> {
        if self.sessions.contains_key(name) {
            self.active_session = Some(name.to_string());
            Ok(())
        } else {
            Err(miette!("Session '{}' not found", name))
        }
    }

    pub fn clear_active(&mut self) {
        self.active_session = None;
    }

    pub fn delete_session(&mut self, name: &str) {
        self.sessions.remove(name);
        if self.active_session.as_deref() == Some(name) {
            self.active_session = None;
        }
    }
}
