//! AEAD implementation using ChaCha20-Poly1305.

use crate::error::ShardError;
use ring::aead::{self, Aad, BoundKey, Nonce, OpeningKey, SealingKey, UnboundKey};

/// Encrypts a payload and returns the ciphertext and authentication tag.
///
/// The header is used as Additional Authenticated Data (AAD).
///
/// # Errors
/// Returns `ShardError::CryptoError` if the key is invalid, the nonce is reused,
/// or the encryption operation fails.
pub fn encrypt(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    header_aad: &[u8],
    payload: &mut [u8],
) -> Result<[u8; 16], ShardError> {
    let unbound_key =
        UnboundKey::new(&aead::CHACHA20_POLY1305, key).map_err(|_| ShardError::CryptoError)?;

    let nonce =
        Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| ShardError::CryptoError)?;

    let mut sealing_key = SealingKey::new(unbound_key, OneNonceSequence::new(nonce));

    let tag = sealing_key
        .seal_in_place_separate_tag(Aad::from(header_aad), payload)
        .map_err(|_| ShardError::CryptoError)?;

    let mut auth_tag = [0u8; 16];
    auth_tag.copy_from_slice(tag.as_ref());
    Ok(auth_tag)
}

/// Decrypts a ciphertext payload and verifies its integrity.
///
/// Implements Section 2.3 (Silent Drop Policy).
///
/// # Errors
/// Returns `ShardError::CryptoError` if the authentication tag is invalid,
/// the AAD does not match, or decryption fails.
pub fn decrypt<'a>(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    header_aad: &[u8],
    ciphertext_and_tag: &'a mut [u8],
) -> Result<&'a mut [u8], ShardError> {
    let unbound_key =
        UnboundKey::new(&aead::CHACHA20_POLY1305, key).map_err(|_| ShardError::CryptoError)?;

    let nonce =
        Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| ShardError::CryptoError)?;

    let mut opening_key = OpeningKey::new(unbound_key, OneNonceSequence::new(nonce));

    let plaintext = opening_key
        .open_in_place(Aad::from(header_aad), ciphertext_and_tag)
        .map_err(|_| ShardError::CryptoError)?;

    Ok(plaintext)
}

/// Helper for ring's AEAD API to use a single nonce.
struct OneNonceSequence(Option<Nonce>);

impl OneNonceSequence {
    /// Creates a new sequence with a single nonce.
    const fn new(nonce: Nonce) -> Self {
        Self(Some(nonce))
    }
}

impl aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        self.0.take().ok_or(ring::error::Unspecified)
    }
}
