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
        /// Remote address (e.g., 127.0.0.1:5000). Optional if in a session.
        #[arg(short, long)]
        to: Option<std::net::SocketAddr>,
        /// Master PSK (Base64). Optional if in a session.
        #[arg(short, long)]
        key: Option<String>,
    },
    /// Start a temporary session to avoid repeating keys and addresses.
    Session {
        /// Name for the session (logging purposes).
        name: String,
        /// Remote address to bind the session to.
        #[arg(short, long)]
        to: std::net::SocketAddr,
        /// Master PSK (Base64).
        #[arg(short, long)]
        key: String,
    },
    /// Clear the current active session.
    Exit,
}
