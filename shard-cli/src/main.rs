//! Main entry point for the Shard CLI.
mod commands;
mod state;

use clap::Parser;
use commands::{Cli, Commands};
use miette::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen => {
            commands::keygen::exec();
        }
        Commands::Listen { port, key, drift } => {
            commands::listen::exec(port, key, drift).await?;
        }
        Commands::Send { message, to, key, drift } => {
            commands::send::exec(message, to, key, drift).await?;
        }
        Commands::Shell { to, key, drift } => {
            commands::shell::exec(to, key, drift).await?;
        }
        Commands::Session { command } => {
            commands::session::exec(command)?;
        }
        Commands::Logout => {
            let mut config = state::Config::load()?;
            config.clear_active();
            config.save()?;
            println!("Logged out from current session successfully.");
        }
    }

    Ok(())
}
