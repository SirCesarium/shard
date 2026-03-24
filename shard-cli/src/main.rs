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
        Commands::Listen { port, key } => {
            commands::listen::exec(port, key).await?;
        }
        Commands::Send { message, to, key } => {
            commands::send::exec(message, to, key).await?;
        }
        Commands::Session { name, to, key } => {
            commands::session::exec(&name, to, key)?;
        }
        Commands::Exit => {
            state::SessionState::clear();
            println!("Session cleared successfully.");
        }
    }

    Ok(())
}
