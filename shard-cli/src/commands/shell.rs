//! Implementation of the interactive shell command.
use crate::commands::util::resolve_target;
use miette::{IntoDiagnostic, Result, miette};
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use shard_sdk::config::ShardConfig;
use shard_sdk::session::ShardSession;
use std::time::Duration;

/// Executes the interactive shell.
pub async fn exec(to: Option<String>, key: Option<String>, drift: u64) -> Result<()> {
    let (master_psk, addr, addr_str) = resolve_target(to, key).await?;

    // 1. Handshake (Performed ONCE)
    println!("Connecting to {addr} ({addr_str})...");
    let mut shard_config = ShardConfig::new(master_psk, addr);
    shard_config.drift_window_ms = drift;
    let session = ShardSession::new(shard_config)
        .await
        .map_err(|e| miette!("Handshake failed: {e}"))?;

    println!("================================================");
    println!(" Shard Interactive Shell Established ");
    println!(" Target: {addr_str}");
    println!(" Type 'exit' or 'quit' to close the session.");
    println!("================================================");

    let mut rl = DefaultEditor::new().into_diagnostic()?;

    loop {
        let readline = rl.readline("shard> ");
        match readline {
            Ok(line) => {
                let input = line.trim();
                if input.is_empty() {
                    continue;
                }

                if input == "exit" || input == "quit" {
                    println!("Closing session...");
                    break;
                }

                let _ = rl.add_history_entry(input);

                // 2. Send Command
                if let Err(e) = session.send_message(input.as_bytes()).await {
                    println!("[ERROR] Failed to send: {e}");
                    continue;
                }

                // 3. Wait for Server Response (Sync-like feel)
                match session.inner_client().receive(Duration::from_secs(2)).await {
                    Ok(payload) => {
                        if let Ok(response) = String::from_utf8(payload) {
                            println!("[RESPONSE] {response}");
                        } else {
                            println!("[RESPONSE] <Binary Data>");
                        }
                    }
                    Err(e) => println!("[TIMEOUT] No response from server ({e})"),
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C received. Closing...");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("EOF received. Closing...");
                break;
            }
            Err(err) => {
                println!("Readline Error: {err:?}");
                break;
            }
        }
    }

    Ok(())
}
