//! Implementation for the keygen command.
use base64::{Engine as _, engine::general_purpose};
use rand::Rng;

/// Generates a new cryptographically secure 32-byte key and prints it in Base64.
pub fn exec() {
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    let encoded = general_purpose::STANDARD.encode(key);

    println!("Generated Master PSK (Base64):");
    println!("{encoded}");
    println!("\nKeep this key secret. You can set it as an env var:");
    println!("export SHARD_KEY={encoded}");
}
