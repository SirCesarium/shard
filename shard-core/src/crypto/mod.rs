//! Cryptographic primitives for the Shard protocol.
//!
//! This module implements AEAD (ChaCha20-Poly1305) and Key Derivation (HKDF-SHA256)
//! as defined in Section 2 of the Shard Protocol Specification v1.0.

pub mod aead;
pub mod hkdf;

use crate::frame::ShardHeader;
use crate::{consts::MAX_PAYLOAD_SIZE, error::ShardError};
use ring::rand::{SecureRandom, SystemRandom};
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

    let sequence_id_raw = header.sequence_id.get();
    let session_key = hkdf::derive_session_key(master_psk, sequence_id_raw)?;

    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(header.sequence_id.as_bytes());

    let rng = SystemRandom::new();
    rng.fill(&mut nonce[8..12])
        .map_err(|_| ShardError::CryptoError)?;

    header.nonce = nonce;

    // The entire header is used as AAD (Offsets 0 to 33).
    let aad = header.as_bytes();

    aead::encrypt(&session_key, &header.nonce, aad, payload)
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
    let internal_error = |e: &str| {
        #[cfg(debug_assertions)]
        println!("[DEBUG] Decryption drop: {e}");
        ShardError::InvalidFrame
    };

    let payload_len = header.payload_len.get() as usize;
    if ciphertext.len() != payload_len {
        return Err(internal_error("Ciphertext length mismatch"));
    }

    let sequence_id = header.sequence_id.get();
    let session_key = hkdf::derive_session_key(master_psk, sequence_id)
        .map_err(|_| internal_error("Key derivation failed"))?;

    let mut contiguous_buffer = [0u8; MAX_PAYLOAD_SIZE + 16];
    let total_len = payload_len + 16;

    contiguous_buffer[..payload_len].copy_from_slice(ciphertext);
    contiguous_buffer[payload_len..total_len].copy_from_slice(auth_tag);

    let aad = header.as_bytes();

    // Decrypt in place within the temporary buffer
    let plaintext = aead::decrypt(
        &session_key,
        &header.nonce,
        aad,
        &mut contiguous_buffer[..total_len],
    )
    .map_err(|_| internal_error("AEAD integrity failure"))?;

    // Copy back the verified plaintext to the original slice
    ciphertext.copy_from_slice(plaintext);

    Ok(())
}

#[cfg(test)]
mod tests {
    use zerocopy::big_endian::{U32, U64};

    use super::*;
    use crate::consts::VERSION;

    #[test]
    fn test_cryptographic_roundtrip() {
        let master_psk = [0u8; 32];
        let mut payload = b"shard protocol test payload".to_vec();
        let original_payload = payload.clone();

        let payload_len_u32 =
            u32::try_from(payload.len()).unwrap_or_else(|_| panic!("Payload length exceeds u32"));

        let mut header = ShardHeader {
            version: VERSION,
            frame_type: 0,
            sequence_id: U64::new(1),
            timestamp: U64::new(0),
            nonce: [0u8; 12],
            payload_len: U32::new(payload_len_u32),
        };

        // Encrypt
        let tag = encrypt_frame_payload(&master_psk, &mut header, &mut payload)
            .unwrap_or_else(|_| panic!("Encryption failed"));

        assert_ne!(payload, original_payload, "Payload must be encrypted");

        // Decrypt
        decrypt_frame_payload(&master_psk, &header, &mut payload, &tag)
            .unwrap_or_else(|_| panic!("Decryption failed"));

        assert_eq!(
            payload, original_payload,
            "Decrypted payload must match original"
        );
    }
}
