//! Cryptographic primitives for the Shard protocol.
//!
//! This module implements AEAD (ChaCha20-Poly1305) and Key Derivation (HKDF-SHA256)
//! as defined in Section 2 of the Shard Protocol Specification v1.0.

pub mod aead;
pub mod hkdf;

use crate::frame::ShardHeader;
use crate::{consts::MAX_PAYLOAD_SIZE, error::ShardError};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, UnboundKey};
use zerocopy::IntoBytes;
use zerocopy::big_endian::U32;

/// Encrypts a plaintext payload using the Shard cryptographic stack.
///
/// Implements Section 2.1 and 2.2:
/// 1. Derives a session key from the master PSK and Sequence ID.
/// 2. Uses the full 34-byte header as AAD.
/// 3. Returns the authentication tag (Poly1305).
///
/// # Errors
/// Returns `ShardError::CryptoError` if key derivation or encryption fails.
pub fn encrypt_frame_payload(
    master_psk: &[u8; 32],
    header: &mut ShardHeader,
    payload: &mut [u8],
) -> Result<[u8; 16], ShardError> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(ShardError::PayloadTooLarge(payload.len()));
    }

    let actual_len = u32::try_from(payload.len()).map_err(|_| ShardError::CryptoError)?;
    header.payload_len = U32::new(actual_len);

    // Section 2.2: KDR implementation
    let session_key = hkdf::derive_session_key(master_psk, header.sequence_id.get())?;

    let unbound_key =
        UnboundKey::new(&CHACHA20_POLY1305, &session_key).map_err(|_| ShardError::CryptoError)?;
    let encryption_key = LessSafeKey::new(unbound_key);

    let nonce = ring::aead::Nonce::try_assume_unique_for_key(&header.nonce)
        .map_err(|_| ShardError::CryptoError)?;

    // Section 2.1: The entire header is used as AAD (Offsets 0 to 33).
    let aad = Aad::from(header.as_bytes());

    let tag = encryption_key
        .seal_in_place_separate_tag(nonce, aad, payload)
        .map_err(|_| ShardError::CryptoError)?;

    let mut auth_tag = [0u8; 16];
    auth_tag.copy_from_slice(tag.as_ref());
    Ok(auth_tag)
}

/// Decrypts a ciphertext payload and verifies its integrity.
///
/// Implements Section 2.3 (Silent Drop Policy):
/// If authentication fails, the operation returns `ShardError::CryptoError`.
///
/// # Errors
/// Returns `ShardError::CryptoError` on authentication tag mismatch or decryption failure.
pub fn decrypt_frame_payload(
    master_psk: &[u8; 32],
    header: &ShardHeader,
    ciphertext: &mut [u8],
    auth_tag: &[u8; 16],
) -> Result<(), ShardError> {
    let internal_error = |_e: &str| {
        #[cfg(debug_assertions)]
        println!("[DEBUG] Decryption drop: {_e}");
        ShardError::CryptoError
    };

    let payload_len =
        usize::try_from(header.payload_len.get()).map_err(|_| ShardError::CryptoError)?;
    if ciphertext.len() != payload_len {
        return Err(internal_error("Ciphertext length mismatch"));
    }

    // Section 2.2: KDR implementation
    let session_key = hkdf::derive_session_key(master_psk, header.sequence_id.get())?;

    let unbound_key =
        UnboundKey::new(&CHACHA20_POLY1305, &session_key).map_err(|_| ShardError::CryptoError)?;
    let decryption_key = LessSafeKey::new(unbound_key);

    let nonce = ring::aead::Nonce::try_assume_unique_for_key(&header.nonce)
        .map_err(|_| ShardError::CryptoError)?;

    // Section 2.1: The entire header is used as AAD.
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
        let master_psk = [0u8; 32];
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
        let tag = encrypt_frame_payload(&master_psk, &mut header, &mut payload)?;

        assert_ne!(payload, original_payload, "Payload must be encrypted");

        // Decrypt
        decrypt_frame_payload(&master_psk, &header, &mut payload, &tag)?;

        assert_eq!(
            payload, original_payload,
            "Decrypted payload must match original"
        );
        Ok(())
    }

    #[test]
    fn test_aad_tamper_detection() -> Result<(), ShardError> {
        use crate::consts::VERSION;
        use zerocopy::big_endian::{U32, U64};

        let master_psk = [0u8; 32];
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
        let tag = encrypt_frame_payload(&master_psk, &mut header, &mut payload)?;

        // ATTACK: Modify Sequence ID in the header after encryption (MITM)
        header.sequence_id = U64::new(101);

        // Decrypt must fail because AEAD includes the header as AAD
        let result = decrypt_frame_payload(&master_psk, &header, &mut payload, &tag);

        assert!(
            result.is_err(),
            "Decryption should fail when header is tampered"
        );
        Ok(())
    }
}
