//! Key Derivation Function (KDR) implementation using HKDF-SHA256.

use crate::consts::VERSION;
use crate::error::ShardError;
use ring::hkdf;

/// Derives a session key from a master PSK and sequence ID.
///
/// As per Section 2.2, the salt is constructed from `SEQUENCE_ID` + `VERSION`.
///
/// # Errors
/// Returns `ShardError::CryptoError` if the HKDF expansion or key filling fails.
pub fn derive_session_key(master_psk: &[u8; 32], sequence_id: u64) -> Result<[u8; 32], ShardError> {
    let mut salt_bytes = [0u8; 9];
    salt_bytes[0..8].copy_from_slice(&sequence_id.to_be_bytes());
    salt_bytes[8] = VERSION;

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt_bytes);
    let prk = salt.extract(master_psk);

    let okm = prk
        .expand(&[b"shard session key"], hkdf::HKDF_SHA256)
        .map_err(|_| ShardError::CryptoError)?;

    let mut session_key = [0u8; 32];
    okm.fill(&mut session_key)
        .map_err(|_| ShardError::CryptoError)?;

    Ok(session_key)
}
