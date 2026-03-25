//! Key Derivation Function (KDR) implementation using HKDF-SHA256.

use crate::error::ShardError;
use ring::hkdf;

/// Derives a session key from a shared secret (ECDH) and a master PSK.
///
/// As per Shard 2.0 SPEC, the salt is the `MasterPSK` and the info is "shard-session-v2".
///
/// # Errors
/// Returns `ShardError::CryptoError` if the HKDF expansion fails.
pub fn derive_session_key_v2(
    shared_secret: &[u8],
    master_psk: &[u8; 32],
) -> Result<[u8; 32], ShardError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, master_psk);
    let prk = salt.extract(shared_secret);

    let okm = prk
        .expand(&[b"shard-session-v2"], hkdf::HKDF_SHA256)
        .map_err(|_| ShardError::CryptoError)?;

    let mut session_key = [0u8; 32];
    okm.fill(&mut session_key)
        .map_err(|_| ShardError::CryptoError)?;

    Ok(session_key)
}
