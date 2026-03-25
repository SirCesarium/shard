//! Cryptographic primitives for the Shard protocol.
//!
//! This module implements AEAD (ChaCha20-Poly1305), Key Derivation (HKDF-SHA256),
//! and Key Agreement (X25519) as defined in the Shard 2.0 Specification.

pub mod aead;
pub mod agreement;
pub mod hkdf;

use crate::frame::ShardHeader;
use crate::{consts::MAX_PAYLOAD_SIZE, error::ShardError};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, UnboundKey};
use zerocopy::IntoBytes;
use zerocopy::big_endian::U32;

/// Encrypts a plaintext payload using a provided 32-byte key.
///
/// 1. Uses the full 34-byte header as AAD.
/// 2. Returns the authentication tag (Poly1305).
///
/// # Errors
/// Returns `ShardError::CryptoError` if encryption fails.
pub fn encrypt_frame_payload(
    key: &[u8; 32],
    header: &mut ShardHeader,
    payload: &mut [u8],
) -> Result<[u8; 16], ShardError> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(ShardError::PayloadTooLarge(payload.len()));
    }

    let actual_len = u32::try_from(payload.len()).map_err(|_| ShardError::CryptoError)?;
    header.payload_len = U32::new(actual_len);

    let unbound_key =
        UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| ShardError::CryptoError)?;
    let encryption_key = LessSafeKey::new(unbound_key);

    let nonce = ring::aead::Nonce::try_assume_unique_for_key(&header.nonce)
        .map_err(|_| ShardError::CryptoError)?;

    // The entire header is used as AAD (Offsets 0 to 33).
    let aad = Aad::from(header.as_bytes());

    let tag = encryption_key
        .seal_in_place_separate_tag(nonce, aad, payload)
        .map_err(|_| ShardError::CryptoError)?;

    let mut auth_tag = [0u8; 16];
    auth_tag.copy_from_slice(tag.as_ref());
    Ok(auth_tag)
}

/// Decrypts a ciphertext payload and verifies its integrity using a provided 32-byte key.
///
/// If authentication fails, the operation returns `ShardError::CryptoError`.
///
/// # Errors
/// Returns `ShardError::CryptoError` on authentication tag mismatch or decryption failure.
pub fn decrypt_frame_payload(
    key: &[u8; 32],
    header: &ShardHeader,
    ciphertext: &mut [u8],
    auth_tag: &[u8; 16],
) -> Result<(), ShardError> {
    #[cfg(debug_assertions)]
    let internal_error = |e: &str| {
        println!("[DEBUG] Decryption drop: {e}");
        ShardError::CryptoError
    };
    #[cfg(not(debug_assertions))]
    let internal_error = |_e: &str| ShardError::CryptoError;

    let payload_len =
        usize::try_from(header.payload_len.get()).map_err(|_| ShardError::CryptoError)?;
    if ciphertext.len() != payload_len {
        return Err(internal_error("Ciphertext length mismatch"));
    }

    let unbound_key =
        UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| ShardError::CryptoError)?;
    let decryption_key = LessSafeKey::new(unbound_key);

    let nonce = ring::aead::Nonce::try_assume_unique_for_key(&header.nonce)
        .map_err(|_| ShardError::CryptoError)?;

    // The entire header is used as AAD.
    let aad = Aad::from(header.as_bytes());

    // Reconstruct the suffixed buffer for ring's API
    let mut buffer = ciphertext.to_vec();
    buffer.extend_from_slice(auth_tag);

    let plaintext = decryption_key
        .open_in_place(nonce, aad, &mut buffer)
        .map_err(|_| internal_error("AEAD integrity failure"))?;

    ciphertext.copy_from_slice(plaintext);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::VERSION;
    use zerocopy::big_endian::{U32, U64};

    #[test]
    fn test_cryptographic_roundtrip() -> Result<(), ShardError> {
        let session_key = [0u8; 32];
        let mut payload = b"shard protocol test payload".to_vec();
        let original_payload = payload.clone();

        let payload_len = u32::try_from(payload.len()).map_err(|_| ShardError::CryptoError)?;

        let mut header = ShardHeader {
            version: VERSION,
            frame_type: 0,
            sequence_id: U64::new(1),
            timestamp: U64::new(0),
            nonce: [0u8; 12],
            payload_len: U32::new(payload_len),
        };

        // Encrypt
        let tag = encrypt_frame_payload(&session_key, &mut header, &mut payload)?;

        assert_ne!(payload, original_payload, "Payload must be encrypted");

        // Decrypt
        decrypt_frame_payload(&session_key, &header, &mut payload, &tag)?;

        assert_eq!(
            payload, original_payload,
            "Decrypted payload must match original"
        );
        Ok(())
    }

    #[test]
    fn test_aad_tamper_detection() -> Result<(), ShardError> {
        let session_key = [0u8; 32];
        let mut payload = b"sensitive data".to_vec();

        let mut header = ShardHeader {
            version: VERSION,
            frame_type: 0,
            sequence_id: U64::new(100),
            timestamp: U64::new(0),
            nonce: [0u8; 12],
            payload_len: U32::new(
                u32::try_from(payload.len()).map_err(|_| ShardError::CryptoError)?,
            ),
        };

        // Encrypt with Sequence ID 100
        let tag = encrypt_frame_payload(&session_key, &mut header, &mut payload)?;

        // ATTACK: Modify Sequence ID in the header after encryption (MITM)
        header.sequence_id = U64::new(101);

        // Decrypt must fail because AEAD includes the header as AAD
        let result = decrypt_frame_payload(&session_key, &header, &mut payload, &tag);

        assert!(
            result.is_err(),
            "Decryption should fail when header is tampered"
        );
        Ok(())
    }

    #[test]
    fn test_x25519_handshake_derivation() -> Result<(), ShardError> {
        use crate::crypto::agreement::{compute_shared_secret, generate_ephemeral_keypair};
        use crate::crypto::hkdf::derive_session_key_v2;

        let master_psk = [0u8; 32];

        // 1. Client generates keypair
        let (client_priv, client_pub) = generate_ephemeral_keypair()?;

        // 2. Server generates keypair
        let (server_priv, server_pub) = generate_ephemeral_keypair()?;

        // 3. Client computes shared secret and session key
        let client_shared = compute_shared_secret(client_priv, &server_pub)?;
        let client_session_key = derive_session_key_v2(&client_shared, &master_psk)?;

        // 4. Server computes shared secret and session key
        let server_shared = compute_shared_secret(server_priv, &client_pub)?;
        let server_session_key = derive_session_key_v2(&server_shared, &master_psk)?;

        // 5. Keys must match
        assert_eq!(client_session_key, server_session_key);

        Ok(())
    }
}
