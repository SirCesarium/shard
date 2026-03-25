//! CLI command definitions and argument parsing.
pub mod keygen;
pub mod listen;
pub mod send;
pub mod session;

use clap::{Parser, Subcommand};

/// Shard CLI: Secure, hardened UDP command delivery.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// Available subcommands for Shard.
#[derive(Subcommand)]
pub enum Commands {
    /// Generate a new 32-byte Master PSK.
    Keygen,
    /// Start a Shard server to listen for encrypted frames.
    Listen {
        /// Port to bind the server.
        #[arg(short, long)]
        port: u16,
        /// Master PSK (Base64). If omitted, looks for `SHARD_KEY` env var or active session.
        #[arg(short, long)]
        key: Option<String>,
    },
    /// Send an encrypted message to a Shard server.
    Send {
        /// The message payload.
        message: String,
        /// Remote address (e.g., example.com:5000). Optional if in a session.
        #[arg(short, long)]
        to: Option<String>,
        /// Master PSK (Base64). Optional if in a session.
        #[arg(short, long)]
        key: Option<String>,
    },
    /// Manage sessions to avoid repeating keys and addresses.
    Session {
        #[command(subcommand)]
        command: SessionCommands,
    },
    /// Logout from the current active session.
    Logout,
}

/// Session management subcommands.
#[derive(Subcommand)]
pub enum SessionCommands {
    /// Create a new session.
    New {
        /// Name for the session.
        name: String,
        /// Remote address (supports domain:port).
        #[arg(short, long)]
        to: String,
        /// Master PSK (Base64).
        #[arg(short, long)]
        key: String,
    },
    /// List all saved sessions.
    List,
    /// Use a specific session by name.
    Use {
        /// The name of the session to activate.
        name: String,
    },
    /// Delete a session.
    Delete {
        /// The name of the session to remove.
        name: String,
    },
}
