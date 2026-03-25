//! Implementation of the session management commands.
use crate::commands::SessionCommands;
use crate::state::Config;
use miette::Result;

/// Executes session subcommands.
pub fn exec(command: SessionCommands) -> Result<()> {
    let mut config = Config::load()?;

    match command {
        SessionCommands::New { name, to, key } => {
            if !key.starts_with("env:") {
                println!("[!] SECURITY WARNING: Storing keys in plain text is not recommended.");
                println!(
                    "    Use '--key env:YOUR_VAR' to reference an environment variable instead."
                );
            }
            config.set_session(name.clone(), to.clone(), key);
            config.save()?;
            println!("Session '{name}' created and activated.");
            println!("Target: {to}");
        }
        SessionCommands::List => {
            if config.sessions.is_empty() {
                println!("No sessions found.");
                return Ok(());
            }

            println!("{:<15} {:<25} Status", "Name", "Target");
            println!("{:-<50}", "");

            for (name, session) in &config.sessions {
                let status = if config.active_session.as_ref() == Some(name) {
                    "Active"
                } else {
                    ""
                };
                println!("{:<15} {:<25} {}", name, session.remote_addr, status);
            }
        }
        SessionCommands::Use { name } => {
            config.use_session(&name)?;
            config.save()?;
            println!("Switched to session '{name}'.");
        }
        SessionCommands::Delete { name } => {
            config.delete_session(&name);
            config.save()?;
            println!("Session '{name}' deleted.");
        }
    }

    Ok(())
}
