//! Key agreement implementation using X25519 (ECDH).

use crate::error::ShardError;
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::SystemRandom;

/// Generates an ephemeral X25519 keypair.
///
/// Returns the private key handle and the serialized public key (32 bytes).
///
/// # Errors
/// Returns `ShardError::CryptoError` if key generation fails.
pub fn generate_ephemeral_keypair() -> Result<(EphemeralPrivateKey, [u8; 32]), ShardError> {
    let rng = SystemRandom::new();
    let private_key =
        EphemeralPrivateKey::generate(&X25519, &rng).map_err(|_| ShardError::CryptoError)?;

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(
        private_key
            .compute_public_key()
            .map_err(|_| ShardError::CryptoError)?
            .as_ref(),
    );

    Ok((private_key, public_key))
}

/// Computes the shared secret using a local private key and a peer's public key.
///
/// Returns the raw shared secret.
///
/// # Errors
/// Returns `ShardError::CryptoError` if the agreement operation fails.
pub fn compute_shared_secret(
    private_key: EphemeralPrivateKey,
    peer_public_key: &[u8; 32],
) -> Result<Vec<u8>, ShardError> {
    let peer_public_key_unparsed = UnparsedPublicKey::new(&X25519, peer_public_key);

    agreement::agree_ephemeral(private_key, &peer_public_key_unparsed, |shared_secret| {
        Ok(shared_secret.to_vec())
    })
    .map_err(|_| ShardError::CryptoError)?
}
